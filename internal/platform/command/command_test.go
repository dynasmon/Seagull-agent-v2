package command

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// A program the test writes as a shell script, run as the agent runs one:
// by its full path and with nothing in its environment.
func program(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the agent runs the programs of the host on linux alone")
	}
	path := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAProgramRunsWithTheArgumentsItIsGivenAndAnEmptyEnvironment(t *testing.T) {
	t.Setenv("SEAGULL_SECRET", "kept by the agent alone")
	t.Setenv("LANG", "pt_BR.UTF-8")
	ran := program(t, `for argument in "$@"; do printf '%s\n' "$argument"; done
printf '%s %s %s\n' "${SEAGULL_SECRET-unset}" "${LANG-unset}" "${HOME-unset}"
`)
	written, err := Output(t.Context(), ran, []string{"--show", "a value; with $(spaces)", ""}, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(written), "--show\na value; with $(spaces)\n\nunset unset unset\n"; got != want {
		t.Errorf("the program wrote %q, want its arguments and nothing of the agent's environment, %q", got, want)
	}
}

func TestAProgramTheHostDoesNotHaveIsAbsent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent runs the programs of the host on linux alone")
	}
	_, err := Output(t.Context(), filepath.Join(t.TempDir(), "dpkg-query"), nil, 1<<10)
	if !errors.Is(err, ErrAbsent) {
		t.Errorf("running a program that is not there reported %v, want ErrAbsent", err)
	}
}

func TestAProgramThatFailsIsReportedWithTheLastLineItComplained(t *testing.T) {
	ran := program(t, `echo 'written before it failed'
echo 'Failed to connect to bus: something else first' >&2
echo 'Failed to connect to bus: Address family not supported by protocol' >&2
echo >&2
exit 3
`)
	_, err := Output(t.Context(), ran, nil, 1<<10)
	var failed *Failure
	if !errors.As(err, &failed) {
		t.Fatalf("a program that exits 3 reported %v, want a Failure", err)
	}
	if failed.Program != "program" || failed.Said != "Failed to connect to bus: Address family not supported by protocol" || !strings.Contains(failed.Err.Error(), "exit status 3") {
		t.Errorf("the failure says %+v", failed)
	}
	if !strings.Contains(err.Error(), "Address family not supported") {
		t.Errorf("the failure reads %q", err)
	}
}

func TestWhatAProgramComplainsOfIsBoundedAndEscaped(t *testing.T) {
	ran := program(t, `/usr/bin/head -c 100000 /dev/zero | /usr/bin/tr '\0' 'x' >&2
printf '\nthe last \033[31mline %s\n' "$(/usr/bin/head -c 500 /dev/zero | /usr/bin/tr '\0' 'y')" >&2
exit 1
`)
	_, err := Output(t.Context(), ran, nil, 1<<10)
	var failed *Failure
	if !errors.As(err, &failed) {
		t.Fatalf("a failing program reported %v", err)
	}
	if len(failed.Said) > 200 || !strings.HasPrefix(failed.Said, `"the last \x1b[31mline yyy`) || !strings.HasSuffix(failed.Said, "...") {
		t.Errorf("the program is said to have complained %q", failed.Said)
	}
}

func TestWhatAProgramWritesUpToTheBoundIsReadWhole(t *testing.T) {
	ran := program(t, `/usr/bin/head -c 4096 /dev/zero`)
	written, err := Output(t.Context(), ran, nil, 4096)
	if err != nil || len(written) != 4096 {
		t.Errorf("a program that wrote the bound gave %d bytes and %v", len(written), err)
	}
}

func TestAProgramThatWritesBeyondTheBoundIsStoppedAndNothingIsKept(t *testing.T) {
	ran := program(t, `/usr/bin/head -c 8192 /dev/zero
exec /bin/sleep 600
`)
	began := time.Now()
	written, err := Output(t.Context(), ran, nil, 4096)
	if !errors.Is(err, ErrTooLong) || written != nil {
		t.Errorf("a program that wrote twice the bound gave %d bytes and %v, want nothing and ErrTooLong", len(written), err)
	}
	if took := time.Since(began); took > 10*time.Second {
		t.Errorf("the program was stopped after %s", took)
	}
}

func TestAProgramEndsWithTheContextItRunsIn(t *testing.T) {
	ran := program(t, `exec /bin/sleep 600`)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err := Output(ctx, ran, nil, 1<<10)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a program that outlived its context reported %v", err)
	}
	if took := time.Since(began); took > 10*time.Second {
		t.Errorf("the program was stopped after %s", took)
	}
}

func TestAProgramThatLeavesAChildBehindIsNotWaitedOnForever(t *testing.T) {
	ran := program(t, `/bin/sleep 600 &
echo 'done'
`)
	began := time.Now()
	written, err := Output(t.Context(), ran, nil, 1<<10)
	if took := time.Since(began); took > 10*time.Second {
		t.Errorf("a program whose child kept its output open was waited on for %s", took)
	}
	if err == nil && !slices.Equal(written, []byte("done\n")) {
		t.Errorf("the program wrote %q", written)
	}
}
