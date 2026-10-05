package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
)

func notes(t *testing.T, failure error) *[]journal.Note {
	t.Helper()
	var held []journal.Note
	before := noted
	noted = func(note journal.Note) error {
		held = append(held, note)
		return failure
	}
	t.Cleanup(func() { noted = before })
	return &held
}

func TestWhatChangesTheInstallationIsRecordedInTheSystemJournal(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	renewing := signing.renewing(t, "", 0)
	rewrite(t, path, state, map[string]string{"server": servers("https://gateway.example:8443", renewing.URL, trustBundle(path))})
	recorded := notes(t, nil)
	var stdout, stderr bytes.Buffer
	var requested []byte
	commands := []struct {
		args  []string
		event string
		code  int
	}{
		{args: []string{"installation", "replace"}, event: "installation_not_replaced", code: 1},
		{args: []string{"enrollment", "renew"}, event: "credential_not_renewed", code: 1},
		{args: []string{"enrollment", "request", "web 01"}, event: "enrollment_not_requested", code: 1},
		{args: []string{"enrollment", "request", "web-01"}, event: "enrollment_requested"},
		{args: []string{"enrollment", "import", filepath.Join(t.TempDir(), "absent.pb")}, event: "credential_not_imported", code: 1},
		{event: "credential_imported"},
		{args: []string{"enrollment", "renew"}, event: "credential_renewed"},
		{args: []string{"config", "check"}},
		{args: []string{"config", "print"}},
		{args: []string{"status"}, code: 1},
		{args: []string{"installation", "replace"}, event: "installation_replaced"},
	}
	for _, command := range commands {
		args := command.args
		if args == nil {
			args = []string{"enrollment", "import", saved(t, signing.issue(t, requested, nil))}
		}
		stdout.Reset()
		stderr.Reset()
		held := len(*recorded)
		if code := run(append([]string{"-config", path}, args...), &stdout, &stderr); code != command.code {
			t.Fatalf("%v exited %d:\n%s", args, code, stderr.String())
		}
		if command.event == "enrollment_requested" {
			requested = bytes.Clone(stdout.Bytes())
		}
		switch noted := (*recorded)[held:]; {
		case command.event == "" && len(noted) != 0:
			t.Errorf("%v, which changes nothing, recorded %+v", args, noted)
		case command.event != "" && (len(noted) != 1 || noted[0].Fields["SEAGULL_EVENT"] != command.event || noted[0].Identifier != "seagull-agent"):
			t.Errorf("%v recorded %+v, want %s", args, noted, command.event)
		case command.event != "":
			var said map[string]any
			if err := json.Unmarshal([]byte(noted[0].Message), &said); err != nil || said["msg"] != command.event || said["config"] != path {
				t.Errorf("%v recorded %q: %v", args, noted[0].Message, err)
			}
			if failed := strings.Contains(command.event, "_not_"); failed != (noted[0].Priority == 4) || failed == (said["error"] == nil) {
				t.Errorf("%v recorded at priority %d: %v", args, noted[0].Priority, said)
			}
		}
	}
	events := map[string]map[string]any{}
	for _, note := range *recorded {
		var said map[string]any
		if err := json.Unmarshal([]byte(note.Message), &said); err == nil {
			events[note.Fields["SEAGULL_EVENT"]] = said
		}
	}
	imported, renewed, replaced := events["credential_imported"], events["credential_renewed"], events["installation_replaced"]
	if imported["agent_id"] != "web-01" || imported["credential_generation"] != float64(1) || imported["installation_id"] == nil ||
		renewed["credential_generation"] != float64(2) || renewed["key"] != "kept" || renewed["installation_id"] != imported["installation_id"] ||
		replaced["replaces"] != imported["installation_id"] || replaced["installation_id"] == imported["installation_id"] || replaced["state"] != state {
		t.Errorf("the journal records %v, %v and %v", imported, renewed, replaced)
	}
	if refused := events["enrollment_not_requested"]; refused["agent_id"] != "web 01" {
		t.Errorf("a refused request was recorded as %v", refused)
	}
}

func TestACommandTheJournalKeepsNoRecordOfStillDoesWhatItWasAskedTo(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	serveStopped(t, path)
	notes(t, errors.New("reach journald: dial unixgram /run/systemd/journal/socket: connect: no such file or directory"))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "installation", "replace"}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stderr.String(), "the system journal holds no record of what this command did: reach journald") {
		t.Fatalf("exit code %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	if replaced, err := filepath.Glob(filepath.Join(state, "replaced", "*", "installation.json")); err != nil || len(replaced) != 1 {
		t.Errorf("the installation was not replaced: %q %v", replaced, err)
	}
}
