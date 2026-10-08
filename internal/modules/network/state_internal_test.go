package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

func written(t *testing.T) *state {
	t.Helper()
	read := reading(
		own(listens(sockets.TCP, "0.0.0.0:22", 0, 1), listens(sockets.UDP, "[::]:5353", 991, 2),
			talks(sockets.TCP, "10.0.0.5:22", "203.0.113.7:51514", sockets.Established, 0, 3),
			talks(sockets.TCP, "10.0.0.5:41001", "198.51.100.1:443", sockets.TimeWait, 0, 0)),
		other(9, 500, seenAt.Add(-time.Hour), listens(sockets.TCP, "0.0.0.0:80", 33, 4)),
	)
	read.Holders = map[uint64][]sockets.Process{1: {{PID: 900, Name: "sshd \xff", StartedAt: seenAt.Add(-time.Hour)}}}
	held, _ := rounds(t, nil, func(c *comparison) { c.complete = true }, read)
	return held
}

func TestWhatTheModuleWritesDownReadsBackAsItWas(t *testing.T) {
	held := written(t)
	content, err := encode(held)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decode(content)
	if err != nil {
		t.Fatalf("what the module wrote down does not read back: %v\n%s", err, content)
	}
	rewritten, err := encode(again)
	if err != nil || !bytes.Equal(content, rewritten) {
		t.Errorf("what the module wrote down reads back as\n%s\nnot\n%s", rewritten, content)
	}
	sshd := again.spaces[0].listeners[listening{sockets.TCP, netip.MustParseAddr("0.0.0.0"), 22}]
	if len(sshd.processes) != 1 || !sshd.processes[0].same(holder{PID: 900, Started: seenAt.Add(-time.Hour)}) || sshd.processes[0].Name != `"sshd \xff"` {
		t.Errorf("the listener's holder reads back as %+v", sshd.processes)
	}
	if again.boot != boot || len(again.spaces) != 2 || again.spaces[1].through.PID != 500 || again.spaces[0].connected == nil {
		t.Errorf("the state reads back as %+v", again)
	}
}

func TestWhatTheModuleCannotHaveWrittenIsDamaged(t *testing.T) {
	content, err := encode(written(t))
	if err != nil {
		t.Fatal(err)
	}
	var shaped map[string]any
	if err := json.Unmarshal(content, &shaped); err != nil {
		t.Fatal(err)
	}
	changed := func(change func(map[string]any)) []byte {
		var copied map[string]any
		json.Unmarshal(content, &copied)
		change(copied)
		rewritten, _ := json.Marshal(copied)
		return rewritten
	}
	namespaces := func(state map[string]any) []any { return state["namespaces"].([]any) }
	space := func(state map[string]any, i int) map[string]any { return namespaces(state)[i].(map[string]any) }
	first := func(state map[string]any, i int, field string) map[string]any {
		return space(state, i)[field].([]any)[0].(map[string]any)
	}
	for name, damaged := range map[string][]byte{
		"no json":                   []byte("{"),
		"two states":                append(append([]byte{}, content...), content...),
		"a field it does not write": changed(func(s map[string]any) { s["extra"] = 1 }),
		"format 0":                  changed(func(s map[string]any) { s["format"] = 0 }),
		"no namespace":              changed(func(s map[string]any) { s["namespaces"] = []any{} }),
		"another namespace first":   changed(func(s map[string]any) { n := namespaces(s); n[0], n[1] = n[1], n[0] }),
		"two of its own":            changed(func(s map[string]any) { space(s, 1)["own"] = true }),
		"a listener of no protocol": changed(func(s map[string]any) { first(s, 0, "listeners")["protocol"] = "sctp" }),
		"a listener at no address":  changed(func(s map[string]any) { first(s, 0, "listeners")["address"] = "localhost" }),
		"a listener of no socket":   changed(func(s map[string]any) { first(s, 0, "listeners")["sockets"] = 0 }),
		"accounts out of order":     changed(func(s map[string]any) { first(s, 0, "listeners")["accounts"] = []any{33, 0} }),
		"a listener twice": changed(func(s map[string]any) {
			listeners := space(s, 0)["listeners"].([]any)
			space(s, 0)["listeners"] = append(listeners, listeners[0])
		}),
		"a flow of no direction":     changed(func(s map[string]any) { first(s, 0, "flows")["direction"] = "sideways" }),
		"a flow missed past its end": changed(func(s map[string]any) { first(s, 0, "flows")["missed"] = linger }),
		"a flow of no association":   changed(func(s map[string]any) { first(s, 0, "flows")["association"] = "maybe" }),
		"a holder named past a bound": changed(func(s map[string]any) {
			space(s, 1)["through"].(map[string]any)["name"] = strings.Repeat("x", maxStateText+1)
		}),
		"more holders than it keeps":   changed(func(s map[string]any) { space(s, 1)["earliest"] = make([]any, maxHolders+1) }),
		"a state larger than it keeps": append(bytes.Repeat([]byte(" "), maxState), content...),
	} {
		if _, err := decode(damaged); !errors.Is(err, ErrDamaged) {
			t.Errorf("a state with %s reads as %v", name, err)
		}
	}
	if _, err := decode(changed(func(s map[string]any) { s["format"] = format + 1 })); !errors.Is(err, ErrNewer) {
		t.Errorf("a state a newer agent wrote reads as %v", err)
	}
}

func TestTheStateIsPrivateToTheAgentAndReplacedWhole(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent keeps its state on unix hosts")
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := load(root); !errors.Is(err, errUnwritten) {
		t.Errorf("an installation that never watched the network reads as %v", err)
	}
	content, err := encode(written(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := save(root, content); err != nil {
		t.Fatal(err)
	}
	described, err := os.Stat(filepath.Join(directory, stateFile))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Errorf("the state was written as %v, %v", described, err)
	}
	if held, err := load(root); err != nil || len(held.spaces) != 2 {
		t.Errorf("the state reads back as %+v, %v", held, err)
	}
	for _, name := range []string{".network.json.0123456789abcdef.tmp", ".network.json.tmp", "files.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := discard(root); err != nil {
		t.Fatal(err)
	}
	for name, kept := range map[string]bool{".network.json.0123456789abcdef.tmp": false, ".network.json.tmp": true, "files.json": true, stateFile: true} {
		if _, err := os.Stat(filepath.Join(directory, name)); (err == nil) != kept {
			t.Errorf("after discarding interrupted writes, %s is there: %v", name, err == nil)
		}
	}
	if err := os.Chmod(filepath.Join(directory, stateFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root); !errors.Is(err, ErrInsecure) {
		t.Errorf("a state others may read loads as %v", err)
	}
	if err := os.Remove(filepath.Join(directory, stateFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("files.json", filepath.Join(directory, stateFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root); !errors.Is(err, ErrInsecure) {
		t.Errorf("a state that is a link loads as %v", err)
	}
}

func FuzzWhatTheModuleReadsBackIsWhatItWouldWrite(f *testing.F) {
	f.Add([]byte(`{"format":1,"boot":"","namespaces":[{"key":1,"own":true,"id":"","host":false,"through":{"pid":0,"name":"","started_at":0},"earliest":[],"processes":0,"pending":false,"listeners":[],"flows":[]}]}`))
	f.Add([]byte(`{"format":1,"boot":"b","namespaces":[{"key":1,"own":true,"id":"net:[1]","host":true,"through":{"pid":0,"name":"","started_at":0},"earliest":[{"pid":1,"name":"init","started_at":5}],"processes":1,"pending":false,` +
		`"listeners":[{"protocol":"tcp","address":"::","port":22,"accounts":[0],"sockets":1,"processes":[],"association":"accounts"}],` +
		`"flows":[{"direction":"inbound","protocol":"tcp","remote":"203.0.113.7","port":22,"account":0,"owned":true,"first":1,"last":2,"most":1,"missed":0,"states":["established"],"processes":[],"association":"accounts"}]}]}`))
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := decode(content)
		if err != nil {
			return
		}
		written, err := encode(held)
		if err != nil {
			t.Fatalf("what reads back does not write: %v", err)
		}
		again, err := decode(written)
		if err != nil {
			t.Fatalf("what the module writes does not read back: %v\n%s", err, written)
		}
		if rewritten, _ := encode(again); !bytes.Equal(written, rewritten) {
			t.Errorf("%s reads back as\n%s", written, rewritten)
		}
	})
}
