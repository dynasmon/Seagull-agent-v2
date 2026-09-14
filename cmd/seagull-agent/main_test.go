package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestTheVersionFlagPrintsTheBuildIdentity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	fields := strings.Fields(stdout.String())
	if len(fields) != 4 || fields[0] != "seagull-agent" || fields[2] != runtime.Version() {
		t.Fatalf("build identity %q", stdout.String())
	}
	if platform := runtime.GOOS + "/" + runtime.GOARCH; fields[3] != platform {
		t.Fatalf("build identity names %s, the binary runs on %s", fields[3], platform)
	}
}

func TestAnythingButTheVersionFlagIsAUsageError(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"-verbose"}, {"-version", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit code %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%q: wrote %q to stdout", args, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Errorf("%q: explained nothing on stderr", args)
		}
	}
}
