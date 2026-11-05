package compatibility_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Each protocol-N directory under testdata is the book of every answer an agent
// reads that the backend recorded at the commit its platform.json names, copied
// from that commit's tree by make platform-answers. The backend fails its own
// build when one of them changes without a version decision (its ADR 48), so
// what the agent makes of each is the agent's half of that promise.
type book struct {
	directory string
	platform  bookSource
	Protocol  int          `json:"protocol"`
	Contracts string       `json:"contracts"`
	Answers   []bookAnswer `json:"answers"`
}

type bookSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
}

type bookAnswer struct {
	Name        string          `json:"name"`
	Listener    string          `json:"listener"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Request     string          `json:"request"`
	Asked       string          `json:"asked"`
	IfNoneMatch bool            `json:"if_none_match"`
	Status      int             `json:"status"`
	ContentType string          `json:"content_type"`
	Tagged      bool            `json:"tagged"`
	RetryAfter  bool            `json:"retry_after"`
	Reply       string          `json:"reply"`
	Message     string          `json:"message"`
	Summary     json.RawMessage `json:"summary"`
}

func books(t *testing.T) []book {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "protocol-*", "answers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("no backend's book of answers was copied: make platform-answers BACKEND=<commit>")
	}
	found := make([]book, 0, len(manifests))
	for _, manifest := range manifests {
		recorded := book{directory: filepath.Dir(manifest)}
		strictly(t, manifest, &recorded)
		strictly(t, filepath.Join(filepath.Dir(recorded.directory), "platform.json"), &recorded.platform)
		if recorded.platform.Repository == "" || len(recorded.platform.Commit) != 40 || recorded.platform.Path == "" ||
			recorded.Contracts == "" || filepath.Base(recorded.directory) != filepath.Base(recorded.platform.Path) {
			t.Fatalf("%s does not say which backend commit, contracts and protocol it was copied from", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func strictly(t *testing.T, file string, into any) {
	t.Helper()
	encoded, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		t.Fatalf("decode %s: %v", file, err)
	}
}

func (b book) name() string {
	return filepath.Base(filepath.Dir(b.directory)) + "/" + filepath.Base(b.directory)
}

func (b book) answer(t *testing.T, name string) bookAnswer {
	t.Helper()
	index := slices.IndexFunc(b.Answers, func(answered bookAnswer) bool { return answered.Name == name })
	if index < 0 {
		t.Fatalf("%s recorded no %s", b.name(), name)
	}
	return b.Answers[index]
}

func (b book) file(t *testing.T, name string) []byte {
	t.Helper()
	if name == "" {
		return nil
	}
	held, err := os.ReadFile(filepath.Join(b.directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func (b book) request(t *testing.T, answered bookAnswer) []byte { return b.file(t, answered.Request) }

func (b book) reply(t *testing.T, answered bookAnswer) []byte { return b.file(t, answered.Reply) }
