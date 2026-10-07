//go:build linux

package integrity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func taken(t *testing.T, given Scope) (string, *baseline) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "collection")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range given.Paths {
		finish(t, path, state)
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	held, err := load(root, Scope{Paths: given.Paths[len(given.Paths)-1:]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return state, held
}

func paths(held *baseline) []string {
	_, records := held.records()
	var found []string
	for _, written := range records {
		found = append(found, written.Path)
	}
	slices.Sort(found)
	return found
}

func TestWhatIsWrittenDownReadsBackAsItWasSeen(t *testing.T) {
	base := t.TempDir()
	grow(t, base, 2, 2)
	if err := os.Symlink("d00/f00", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	_, held := taken(t, Scope{Paths: []string{base}})
	content, err := encode(held)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decode(content, Scope{Paths: []string{base}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, first := held.records()
	_, second := again.records()
	if !slices.Equal(first, second) || again.entries != 8 || !again.roots[base].observed {
		t.Fatalf("read back %d entries as %+v, written as %+v", again.entries, second, first)
	}
	for _, written := range second {
		switch {
		case strings.HasSuffix(written.Path, "f01") && !strings.HasPrefix(written.Content, digestPrefix):
			t.Errorf("%s was read back as %+v", written.Path, written)
		case written.Path == filepath.Join(base, "link") && (written.Target != "d00/f00" || written.Kind != "link"):
			t.Errorf("the link was read back as %+v", written)
		case written.Kind == "directory" && !written.Listed:
			t.Errorf("a listed directory was read back as %+v", written)
		}
	}
}

func TestADamagedOrNewerBaselineIsRefused(t *testing.T) {
	base := t.TempDir()
	grow(t, base, 1, 2)
	_, held := taken(t, Scope{Paths: []string{base}})
	content, err := encode(held)
	if err != nil {
		t.Fatal(err)
	}
	var written map[string]any
	if err := json.Unmarshal(content, &written); err != nil {
		t.Fatal(err)
	}
	edited := func(change func(map[string]any, []any)) []byte {
		copied := map[string]any{}
		if err := json.Unmarshal(content, &copied); err != nil {
			t.Fatal(err)
		}
		change(copied, copied["entries"].([]any))
		encoded, err := json.Marshal(copied)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	entry := func(entries []any, suffix string) map[string]any {
		for _, held := range entries {
			if strings.HasSuffix(held.(map[string]any)["path"].(string), suffix) {
				return held.(map[string]any)
			}
		}
		t.Fatalf("no entry ends in %s", suffix)
		return nil
	}
	for name, damaged := range map[string][]byte{
		"not json":            []byte("{"),
		"two baselines":       append(slices.Clone(content), content...),
		"an unknown field":    edited(func(held map[string]any, _ []any) { held["more"] = true }),
		"an older format":     edited(func(held map[string]any, _ []any) { held["format"] = 0 }),
		"a relative path":     edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["path"] = "d00/f00" }),
		"an unknown kind":     edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["kind"] = "door" }),
		"a mode past 07777":   edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["mode"] = 0o10000 }),
		"a listed file":       edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["listed"] = true }),
		"a target of a file":  edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["target"] = "x" }),
		"a short digest":      edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["content"] = "sha256:00" }),
		"an unknown content":  edited(func(_ map[string]any, entries []any) { entry(entries, "f00")["content"] = "maybe" }),
		"content of a folder": edited(func(_ map[string]any, entries []any) { entry(entries, "d00")["content"] = "unreadable" }),
		"a file within a file": edited(func(held map[string]any, entries []any) {
			inner := copied(entry(entries, "f00"))
			inner["path"] = filepath.Join(inner["path"].(string), "inner")
			held["entries"] = append(entries, inner)
		}),
		"an entry twice": edited(func(held map[string]any, entries []any) {
			held["entries"] = append(entries, copied(entry(entries, "f00")))
		}),
		"a path seen unwatched": edited(func(held map[string]any, _ []any) { held["observed"] = []any{"/elsewhere"} }),
		"a bad pattern":         edited(func(held map[string]any, _ []any) { held["exclude"] = []any{"["} }),
	} {
		if _, err := decode(damaged, Scope{Paths: []string{base}}, nil); !errors.Is(err, ErrDamaged) {
			t.Errorf("%s was read as a baseline: %v", name, err)
		}
	}
	newer := edited(func(held map[string]any, _ []any) { held["format"] = 2 })
	if _, err := decode(newer, Scope{Paths: []string{base}}, nil); !errors.Is(err, ErrNewer) {
		t.Errorf("a newer baseline was read: %v", err)
	}
	outside := edited(func(held map[string]any, entries []any) {
		stray := copied(entry(entries, "f00"))
		stray["path"] = "/elsewhere/f00"
		held["entries"] = append(entries, stray)
	})
	if read, err := decode(outside, Scope{Paths: []string{base}}, nil); err != nil || slices.Contains(paths(read), "/elsewhere/f00") {
		t.Errorf("an entry outside what is watched was read as %v, %v", paths(read), err)
	}
}

func copied(held map[string]any) map[string]any {
	made := map[string]any{}
	for key, value := range held {
		made[key] = value
	}
	return made
}

func TestABaselineAnotherAccountCouldChangeIsRefused(t *testing.T) {
	base := t.TempDir()
	grow(t, base, 1, 1)
	state, _ := taken(t, Scope{Paths: []string{base}})
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Chmod(filepath.Join(state, baselineFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root, Scope{Paths: []string{base}}, nil); !errors.Is(err, ErrInsecure) {
		t.Errorf("a baseline others may read was loaded: %v", err)
	}
	if err := os.Rename(filepath.Join(state, baselineFile), filepath.Join(state, "elsewhere.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere.json", filepath.Join(state, baselineFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root, Scope{Paths: []string{base}}, nil); !errors.Is(err, ErrInsecure) {
		t.Errorf("a link in place of the baseline was followed: %v", err)
	}
	if err := os.Remove(filepath.Join(state, baselineFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root, Scope{Paths: []string{base}}, nil); !errors.Is(err, errUnwritten) {
		t.Errorf("no baseline was read as %v", err)
	}
	for _, name := range []string{".files.json.0123456789abcdef.tmp", ".inventory.json.0123456789abcdef.tmp", ".files.json.short.tmp"} {
		if err := os.WriteFile(filepath.Join(state, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := discard(root); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, held := range left {
		names = append(names, held.Name())
	}
	if !slices.Equal(names, []string{".files.json.short.tmp", ".inventory.json.0123456789abcdef.tmp", "elsewhere.json"}) {
		t.Errorf("discarding interrupted writes left %q", names)
	}
}

func TestAScopeThatChangesKeepsWhatItSawWithinTheNewOne(t *testing.T) {
	base := t.TempDir()
	grow(t, base, 2, 2)
	_, held := taken(t, Scope{Paths: []string{base}})
	inner := filepath.Join(base, "d00")

	nested, err := held.rescope(Scope{Paths: []string{base, inner}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !nested.roots[inner].observed || nested.roots[inner].entry == nil || nested.roots[base].entry.child("d00") != nil || nested.count() != 7 {
		t.Errorf("a directory named as a path of its own is held as %+v, %+v", nested.roots[inner], nested.roots[base].entry.children)
	}
	narrowed, err := held.rescope(Scope{Paths: []string{inner}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(narrowed); !slices.Equal(got, []string{inner, filepath.Join(inner, "f00"), filepath.Join(inner, "f01")}) {
		t.Errorf("a narrowed scope holds %q", got)
	}
	excluded, err := held.rescope(Scope{Paths: []string{base}, Exclude: []string{inner, "f01"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(excluded); !slices.Equal(got, []string{base, filepath.Join(base, "d01"), filepath.Join(base, "d01", "f00")}) {
		t.Errorf("a scope leaving things out holds %q", got)
	}
	included, err := excluded.rescope(Scope{Paths: []string{base}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !included.fresh.holds(filepath.Join(inner, "f00")) || !included.fresh.holds(filepath.Join(base, "d01", "f01")) || included.fresh.holds(filepath.Join(base, "d01", "f00")) {
		t.Errorf("what the scope no longer leaves out is held as %+v", included.fresh)
	}
	content, err := encode(included)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decode(content, Scope{Paths: []string{base}}, nil)
	if err != nil || !slices.Equal(again.fresh.paths, []string{inner}) || !slices.Equal(again.fresh.patterns, []string{"f01"}) {
		t.Errorf("what the scope no longer leaves out was read back as %+v, %v", again.fresh, err)
	}
	owned, err := held.rescope(Scope{Paths: []string{base}, Exclude: []string{"*.tmp"}}, []string{inner})
	if err != nil || slices.Contains(paths(owned), inner) {
		t.Errorf("the module's own directory is held: %q, %v", paths(owned), err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"format":1,"paths":["/a"],"exclude":[],"fresh":{"paths":[],"patterns":[]},"observed":["/a"],"entries":[{"path":"/a","kind":"directory","device":1,"inode":2,"links":2,"user":0,"group":0,"mode":493,"size":4096,"modified":1,"changed":1,"listed":true},{"path":"/a/b","kind":"regular","device":1,"inode":3,"links":1,"user":0,"group":0,"mode":420,"size":1,"modified":1,"changed":1,"content":"unreadable"}]}`))
	f.Add([]byte(`{"format":1,"paths":["/a","/a/b"],"exclude":["*.swp"],"fresh":{"paths":["/a/c"],"patterns":["x*"]},"observed":["/a/b"],"entries":[{"path":"/a/b","kind":"link","device":1,"inode":3,"links":1,"user":0,"group":0,"mode":511,"size":1,"modified":1,"changed":1,"target":"x"}]}`))
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := decode(content, Scope{Paths: []string{"/a", "/a/b/c"}, Exclude: []string{"/a/d"}}, nil)
		if err != nil {
			return
		}
		again, err := encode(held)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decode(again, Scope{Paths: []string{"/a", "/a/b/c"}, Exclude: []string{"/a/d"}}, nil); err != nil {
			t.Fatalf("what was written back does not read: %v\n%s", err, again)
		}
	})
}
