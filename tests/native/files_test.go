//go:build linux

package native_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	watchedTree = "/srv/seagull-native-gate"
	hiddenTree  = "/root/seagull-native-gate"
	readDropIn  = "files.conf"
)

func (g *gate) files(t *testing.T) {
	t.Cleanup(func() {
		exec.Command("umount", filepath.Join(watchedTree, "mounted")).Run()
		exec.Command("systemctl", "kill", "--signal=SIGCONT", unit).Run()
		os.RemoveAll(watchedTree)
		os.RemoveAll(hiddenTree)
		os.Remove(filepath.Join(overrides, readDropIn))
		exec.Command("systemctl", "daemon-reload").Run()
	})
	tree := map[string]struct {
		mode    os.FileMode
		content string
	}{
		watchedTree:                                    {mode: os.ModeDir | 0o755},
		filepath.Join(watchedTree, "config"):           {mode: 0o644, content: "first"},
		filepath.Join(watchedTree, "private"):          {mode: 0o600, content: "only root reads this"},
		filepath.Join(watchedTree, "closed"):           {mode: os.ModeDir | 0o700},
		filepath.Join(watchedTree, "closed", "inside"): {mode: 0o644, content: "inside"},
		filepath.Join(watchedTree, "bin"):              {mode: os.ModeDir | 0o755},
		filepath.Join(watchedTree, "bin", "tool"):      {mode: 0o755, content: "#!/bin/sh\n"},
		filepath.Join(watchedTree, "mounted"):          {mode: os.ModeDir | 0o755},
		hiddenTree:                                     {mode: os.ModeDir | 0o700},
		filepath.Join(hiddenTree, "keys"):              {mode: 0o600, content: "ssh-ed25519 AAAA"},
	}
	for _, path := range slices.Sorted(func(yield func(string) bool) {
		for path := range tree {
			if !yield(path) {
				return
			}
		}
	}) {
		held := tree[path]
		var err error
		if held.mode.IsDir() {
			err = os.Mkdir(path, held.mode.Perm())
		} else {
			err = os.WriteFile(path, []byte(held.content), held.mode.Perm())
		}
		if err == nil {
			err = os.Chmod(path, held.mode.Perm())
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	g.watching, g.excluded = []string{watchedTree, hiddenTree}, []string{"*.swp"}
	g.collecting(t, g.collects)
	watched := g.said(t, "files_watched", 0)
	t.Logf("the agent took the baseline of %v entries in %v ns", watched["entries"], watched["took"])
	covered := g.said(t, "files_not_covered", 0)
	if reason := fmt.Sprint(covered["reason"]); covered["level"] != "WARN" || !strings.Contains(reason, "directories it cannot list: 1, such as "+filepath.Join(watchedTree, "closed")) ||
		!strings.Contains(reason, "files whose content it cannot read: 1, such as "+filepath.Join(watchedTree, "private")) ||
		!strings.Contains(fmt.Sprint(covered["error"]), "the module cannot look at a path it was given: "+hiddenTree) ||
		!strings.Contains(fmt.Sprint(covered["recovery"]), "AmbientCapabilities=CAP_DAC_READ_SEARCH") {
		t.Errorf("with the service hiding /root and reading as its own account, the agent said %v", covered)
	}
	g.statusSays(t, false, "\nmodule files: degraded", "the module cannot look at a path it was given: "+hiddenTree, "CAP_DAC_READ_SEARCH")

	config := filepath.Join(watchedTree, "config")
	written := g.after(t, config, "modified", func() { place(t, config, []byte("second")) })
	if fmt.Sprint(written["changes"]) != "[content]" || fmt.Sprint(written["origin"]) != "realtime" {
		t.Errorf("a file written again was reported as %v", written)
	}
	tool := filepath.Join(watchedTree, "bin", "tool")
	moded := g.after(t, tool, "modified", func() {
		if err := syscall.Chmod(tool, 0o4755); err != nil {
			t.Fatal(err)
		}
	})
	if fmt.Sprint(moded["changes"]) != "[mode]" || after(moded)["mode"] != "4755" {
		t.Errorf("a setuid bit set was reported as %v", moded)
	}
	owned := g.after(t, config, "modified", func() {
		if err := os.Lchown(config, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	})
	if fmt.Sprint(owned["changes"]) != "[owner group]" || after(owned)["user"] != float64(65534) || owned["coalesced"] != float64(1) {
		t.Errorf("a file given to nobody was reported as %v", owned)
	}
	swapped := g.after(t, config, "modified", func() {
		if err := os.Remove(config); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/shadow", config); err != nil {
			t.Fatal(err)
		}
	})
	if fmt.Sprint(swapped["changes"]) != "[kind]" || after(swapped)["target"] != "/etc/shadow" || after(swapped)["sha256"] != nil {
		t.Errorf("a file replaced by a link to /etc/shadow was reported as %v", swapped)
	}
	pipe := filepath.Join(watchedTree, "pipe")
	created := g.after(t, pipe, "created", func() {
		if err := syscall.Mkfifo(pipe, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if after(created)["kind"] != "pipe" {
		t.Errorf("a pipe was reported as %v", created)
	}
	renamed := filepath.Join(watchedTree, "bin", "renamed")
	moved := g.after(t, renamed, "renamed", func() {
		if err := os.Rename(tool, renamed); err != nil {
			t.Fatal(err)
		}
	})
	if moved["previous"] != tool {
		t.Errorf("a rename was reported as %v", moved)
	}
	brief := filepath.Join(watchedTree, "brief")
	g.after(t, brief, "transient", func() {
		place(t, filepath.Join(watchedTree, ".config.swp"), []byte("left out"))
		place(t, brief, nil)
		if err := os.Remove(brief); err != nil {
			t.Fatal(err)
		}
	})

	queued, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events")
	if err != nil {
		t.Fatal(err)
	}
	most, err := strconv.Atoi(strings.TrimSpace(string(queued)))
	if err != nil {
		t.Fatal(err)
	}
	run(t, "systemctl", "kill", "--signal=SIGSTOP", unit)
	for i := range most/2 + 100 {
		path := filepath.Join(watchedTree, "burst-"+strconv.Itoa(i))
		place(t, path, nil)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	survivor := filepath.Join(watchedTree, "survivor")
	place(t, survivor, []byte("written while the agent could not read what the kernel said"))
	run(t, "systemctl", "kill", "--signal=SIGCONT", unit)
	g.said(t, "files_hints_lost", 0)
	if walked := g.said(t, "files_walked", 0); walked["because"] != "overflow" {
		t.Errorf("after the kernel dropped what it had to say, the agent walked %v", walked)
	}
	if found := g.change(t, survivor, "created"); found["origin"] != "reconciliation" {
		t.Errorf("a file written while the kernel's queue overflowed was reported as %v", found)
	}
	for _, change := range g.changes(t) {
		path := fmt.Sprint(change["path"])
		if strings.HasSuffix(path, ".swp") || strings.HasPrefix(path, filepath.Join(watchedTree, "burst-")) {
			t.Errorf("the agent reported %v", change)
		}
	}

	place(t, filepath.Join(overrides, readDropIn), []byte("[Service]\nProtectHome=read-only\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH\nAmbientCapabilities=CAP_DAC_READ_SEARCH\n"))
	run(t, "systemctl", "daemon-reload")
	g.restarted(t)
	if granted := await(t, g.invocation, "agent_privileges", 30*time.Second); granted["level"] != "INFO" || fmt.Sprint(granted["capabilities"]) != "[CAP_DAC_READ_SEARCH]" {
		t.Errorf("with the drop-in and the files module enabled, the agent reported %v", granted)
	}
	if walked := g.said(t, "files_walked", 0); walked["because"] != "start" {
		t.Errorf("started again, the agent walked %v", walked)
	}
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "files_not_covered" {
			t.Errorf("with the drop-in, the agent said %v", entry)
		}
	}
	if found := g.changes(t); len(found) > 0 {
		t.Errorf("what the agent could not read before was reported as changes once it could: %v", found)
	}
	g.statusSays(t, true, "\nmodule files: running")
	keys := filepath.Join(hiddenTree, "keys")
	changed := g.after(t, keys, "modified", func() {
		if err := os.WriteFile(keys, []byte("ssh-ed25519 BBBB"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if fmt.Sprint(changed["changes"]) != "[content]" || after(changed)["sha256"] == nil {
		t.Errorf("a key added to a file only root reads was reported as %v", changed)
	}

	mounted := filepath.Join(watchedTree, "mounted")
	run(t, "mount", "-t", "tmpfs", "-o", "size=1m,mode=0755", "seagull-native-gate", mounted)
	place(t, filepath.Join(mounted, "beyond"), []byte("on another filesystem"))
	g.restarted(t)
	notCovered := g.said(t, "files_not_covered", 0)
	if !strings.Contains(fmt.Sprint(notCovered["reason"]), "directories on another filesystem, which it does not walk: 1, such as "+mounted) {
		t.Errorf("with a filesystem mounted within what it watches, the agent said %v", notCovered)
	}
	if covering := g.change(t, mounted, "modified"); fmt.Sprint(covering["changes"]) != "[identity]" {
		t.Errorf("a filesystem mounted over a directory it watched was reported as %v", covering)
	}
	run(t, "umount", mounted)
	for _, change := range g.changes(t) {
		if strings.HasPrefix(fmt.Sprint(change["path"]), mounted+"/") {
			t.Errorf("the agent reported what another filesystem holds: %v", change)
		}
	}

	g.watching, g.excluded = nil, nil
	g.collecting(t, g.collects)
	if stopped := await(t, g.invocation, "module_stopped", 30*time.Second); stopped["module"] != "files" {
		t.Errorf("the agent stopped %v", stopped)
	}
	if held := watchers(t, property(t, "MainPID")); held != 0 {
		t.Errorf("with the files module disabled, the agent holds %d inotify instances", held)
	}
	if err := os.Remove(filepath.Join(overrides, readDropIn)); err != nil {
		t.Fatal(err)
	}
	run(t, "systemctl", "daemon-reload")
	g.restarted(t)
}

func after(change map[string]any) map[string]any {
	held, _ := change["after"].(map[string]any)
	return held
}

// said waits for the files module to log a message for the skip-th time and
// more, in the invocation running now.
func (g *gate) said(t *testing.T, message string, skip int) map[string]any {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		var found []map[string]any
		for _, entry := range journal(t, g.invocation) {
			if entry["msg"] == message && entry["module"] == "files" {
				found = append(found, entry)
			}
		}
		if len(found) > skip {
			return found[skip]
		}
		if time.Now().After(deadline) {
			t.Fatalf("the files module logged no %s:\n%s", message, answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (g *gate) changes(t *testing.T) []map[string]any {
	t.Helper()
	var found []map[string]any
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "file_changed" {
			found = append(found, entry)
		}
	}
	return found
}

func (g *gate) change(t *testing.T, path, operation string) map[string]any {
	t.Helper()
	return g.changeSince(t, path, operation, nil)
}

// after does what it is handed and waits for the agent to report it.
func (g *gate) after(t *testing.T, path, operation string, act func()) map[string]any {
	t.Helper()
	earlier := g.changes(t)
	act()
	return g.changeSince(t, path, operation, earlier)
}

func (g *gate) changeSince(t *testing.T, path, operation string, earlier []map[string]any) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		found := g.changes(t)
		for _, change := range found[min(len(earlier), len(found)):] {
			if change["path"] == path && change["operation"] == operation {
				return change
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent did not report %s %s:\n%s", path, operation, answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func watchers(t *testing.T, pid string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("/proc", pid, "fd"))
	if err != nil {
		t.Fatal(err)
	}
	counted := 0
	for _, entry := range entries {
		if target, err := os.Readlink(filepath.Join("/proc", pid, "fd", entry.Name())); err == nil && target == "anon_inode:inotify" {
			counted++
		}
	}
	return counted
}
