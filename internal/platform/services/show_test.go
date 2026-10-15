package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEachUnitIsShownAsSystemdHoldsItUnderTheNameItKnowsItBy(t *testing.T) {
	held := faked(t, "[]", "[]")
	write(t, filepath.Join(held.directory, "show"), "Id=ssh.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n"+
		"Id=ssh.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n"+
		"Id=rpcbind.socket\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n\n"+
		"UnitFileState=masked\nActiveState=inactive\nLoadState=masked\nId=telnet.socket\n")
	shown, err := Show(context.Background(), []string{"ssh.service", "sshd.service", "rpcbind.socket", "telnet.socket"})
	if err != nil {
		t.Fatalf("show the units: %v", err)
	}
	want := []Unit{
		{Asked: "ssh.service", ID: "ssh.service", Load: "loaded", Active: "active", File: "enabled"},
		{Asked: "sshd.service", ID: "ssh.service", Load: "loaded", Active: "active", File: "enabled"},
		{Asked: "rpcbind.socket", ID: "rpcbind.socket", Load: "not-found", Active: "inactive"},
		{Asked: "telnet.socket", ID: "telnet.socket", Load: "masked", Active: "inactive", File: "masked"},
	}
	if len(shown) != len(want) {
		t.Fatalf("%d units were shown, and %d asked for", len(shown), len(want))
	}
	for index := range want {
		if shown[index] != want[index] {
			t.Errorf("unit %d is shown as %+v, want %+v", index, shown[index], want[index])
		}
	}
	arguments, err := os.ReadFile(filepath.Join(held.directory, "arguments"))
	if err != nil || !strings.Contains(string(arguments), "show --no-pager --property=Id,LoadState,ActiveState,UnitFileState -- ssh.service sshd.service") {
		t.Fatalf("systemctl was run as %q: %v", arguments, err)
	}
}

func TestWhatIsNoUnitIsNeverHandedToSystemctl(t *testing.T) {
	faked(t, "[]", "[]")
	for _, name := range []string{"--root=/", "ssh service", "", "ssh;reboot", strings.Repeat("u", 256) + ".service", "nosuffix"} {
		if _, err := Show(context.Background(), []string{name}); err == nil {
			t.Errorf("%q was handed to systemctl", name)
		}
	}
}

func TestWhatSystemctlSaysOfFewerUnitsThanAskedIsUnreadable(t *testing.T) {
	held := faked(t, "[]", "[]")
	write(t, filepath.Join(held.directory, "show"), "Id=ssh.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n")
	if _, err := Show(context.Background(), []string{"ssh.service", "cron.service"}); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("an answer about one of two units was answered %v", err)
	}
	write(t, filepath.Join(held.directory, "complaint"), "Failed to connect to bus: Permission denied\n")
	if _, err := Show(context.Background(), []string{"ssh.service"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("a systemctl that cannot reach systemd was answered %v", err)
	}
}
