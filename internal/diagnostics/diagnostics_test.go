package diagnostics_test

import (
	"encoding/json"
	"errors"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
)

func TestATextIsWrittenAsAKilobyteAtMost(t *testing.T) {
	for _, written := range []string{strings.Repeat("x", 4<<10), strings.Repeat("é", 2<<10), strings.Repeat("x", 1023) + "é"} {
		encoded, err := json.Marshal(diagnostics.Text(written))
		if err != nil {
			t.Fatal(err)
		}
		var read string
		if err := json.Unmarshal(encoded, &read); err != nil {
			t.Fatal(err)
		}
		if len(read) > 1<<10+len("...") || !strings.HasSuffix(read, "...") || !utf8.ValidString(read) || !strings.HasPrefix(written, strings.TrimSuffix(read, "...")) {
			t.Errorf("a text of %d bytes was written as %d bytes: %q", len(written), len(read), read[max(len(read)-8, 0):])
		}
	}
	if encoded, _ := json.Marshal(diagnostics.Text("short")); string(encoded) != `"short"` {
		t.Errorf("a short text was written as %s", encoded)
	}
}

func TestWhatWasReadIsKeptAsReadAndWhatWasNotSaysWhy(t *testing.T) {
	took := diagnostics.Took("/etc/seagull-agent/agent.json", map[string]int{"format": 1})
	if took.From != "/etc/seagull-agent/agent.json" || string(took.Held) != `{"format":1}` || took.Unread != "" {
		t.Errorf("what was read is kept as %+v", took)
	}
	missed := diagnostics.Missed("/var/lib/seagull-agent/status", errors.New("the agent has written no status"), "start the agent")
	if missed.Held != nil || missed.Unread != "the agent has written no status" || missed.Recovery != "start the agent" {
		t.Errorf("what was not read is kept as %+v", missed)
	}
	if unwritten := diagnostics.Took("a channel", make(chan int)); unwritten.Held != nil || !strings.Contains(string(unwritten.Unread), "cannot be written down") {
		t.Errorf("what cannot be written down is kept as %+v", unwritten)
	}
}

func TestTheBuildIsWhatGoStampedOnTheBinary(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("this binary carries no build information")
	}
	versions := map[string]int{"protocol_version": 1}
	built := diagnostics.Built("seagull-agent (devel)", versions, info)
	if built.Identity != "seagull-agent (devel)" || built.Versions["protocol_version"] != 1 || built.Go != diagnostics.Text(runtime.Version()) ||
		built.Path != diagnostics.Text(info.Path) || built.Main.Path != diagnostics.Text(info.Main.Path) {
		t.Errorf("the build is described as %+v", built)
	}
	for _, setting := range info.Settings {
		if built.Settings[diagnostics.Text(setting.Key)] != diagnostics.Text(setting.Value) {
			t.Errorf("the build setting %s is described as %q", setting.Key, built.Settings[diagnostics.Text(setting.Key)])
		}
	}
	if len(built.Dependencies) != len(info.Deps) {
		t.Errorf("the build names %d dependencies, and the binary was built with %d", len(built.Dependencies), len(info.Deps))
	}
	if unstamped := diagnostics.Built("seagull-agent (devel)", versions, nil); unstamped.Go != "" || unstamped.Settings != nil || unstamped.Identity == "" {
		t.Errorf("a binary that carries no build information is described as %+v", unstamped)
	}
}

func TestABundleSaysWhichOfItsPartsWereNotRead(t *testing.T) {
	bundle := diagnostics.Bundle{
		Status:      diagnostics.Missed("status", errors.New("the agent has written no status"), "start the agent"),
		Authorities: diagnostics.Authorities{Adopted: &diagnostics.Set{Unread: "damaged"}},
		Logs:        diagnostics.Logs{Unread: []diagnostics.Text{"the account the agent runs as may not read the system journal"}},
	}
	want := []string{
		"status: the agent has written no status",
		"adopted authorities: damaged",
		"logs: the account the agent runs as may not read the system journal",
	}
	if unread := bundle.Unread(); !slices.Equal(unread, want) {
		t.Errorf("the bundle says it did not read %q, want %q", unread, want)
	}
}
