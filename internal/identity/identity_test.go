package identity_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
)

const childDirectory = "SEAGULL_IDENTITY_TEST_DIRECTORY"

var randomUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const (
	firstKey  = "3f5a0c1d2e4b6a7988796a5b4c3d2e1f0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	secondKey = "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa99887766554433221100"
)

const enrolledState = `{
  "format": 1,
  "installation_id": "5f0b6a1e-3c2d-4b8f-9a7e-1d2c3b4a5f6e",
  "created_at": "2026-09-16T17:00:00Z",
  "enrollment": {
    "agent_id": "web-01",
    "generation": 2,
    "key_id": "3f5a0c1d2e4b6a7988796a5b4c3d2e1f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "certificate": {
      "subject": "web-01",
      "serial": "0a1b2c3d",
      "fingerprint_sha256": "b4c1d2e3f40516273849a5b6c7d8e9f00112233445566778899aabbccddeeff0",
      "not_before": "2026-09-01T00:00:00Z",
      "not_after": "2026-11-30T00:00:00Z"
    }
  }
}
`

// A child holds the installation it opens until its standard input closes, so
// every other child that opens the same directory meanwhile is refused.
func TestMain(m *testing.M) {
	if directory, ok := os.LookupEnv(childDirectory); ok {
		os.Exit(child(directory))
	}
	os.Exit(m.Run())
}

func child(directory string) int {
	input := bufio.NewReader(os.Stdin)
	if _, err := input.ReadString('\n'); err != nil {
		return 1
	}
	installation, err := identity.Open(directory)
	switch {
	case errors.Is(err, identity.ErrLocked):
		fmt.Println("locked")
	case err != nil:
		fmt.Println("failed", err)
	default:
		defer installation.Close()
		fmt.Println("opened", installation.ID(), installation.Created())
	}
	_, _ = io.Copy(io.Discard, input)
	return 0
}

func TestANewDirectoryBecomesAPrivateUnenrolledInstallation(t *testing.T) {
	directory := stateDirectory(t)
	installation := open(t, directory)

	if !installation.Created() || !randomUUID.MatchString(installation.ID()) {
		t.Fatalf("opened installation %q, created: %t", installation.ID(), installation.Created())
	}
	if enrolled, ok := installation.Enrollment(); ok {
		t.Fatalf("a new installation is enrolled as %+v", enrolled)
	}
	for path, want := range map[string]os.FileMode{
		directory: 0o700,
		filepath.Join(directory, "installation.json"): 0o600,
	} {
		described, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("describe %s: %v", path, err)
		}
		if got := described.Mode().Perm(); got != want {
			t.Errorf("%s was created with %s, want %s", path, got, want)
		}
	}
}

func TestReopeningAnInstallationKeepsItsIdentity(t *testing.T) {
	directory := stateDirectory(t)
	first := open(t, directory)
	created := first.ID()
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := open(t, directory)
	if reopened.ID() != created || reopened.Created() {
		t.Fatalf("reopened %q (created: %t), the installation is %q", reopened.ID(), reopened.Created(), created)
	}
}

func TestEveryInstallationDrawsAnIdentifierOfItsOwn(t *testing.T) {
	drawn := map[string]bool{}
	for range 64 {
		installation := open(t, stateDirectory(t))
		if drawn[installation.ID()] {
			t.Fatalf("two installations on one machine drew %s", installation.ID())
		}
		drawn[installation.ID()] = true
	}
}

func TestAStateWrittenInThisFormatReadsAsWritten(t *testing.T) {
	directory := stateDirectory(t)
	writeState(t, directory, enrolledState)

	installation := open(t, directory)
	enrolled, ok := installation.Enrollment()
	want := enrollment("web-01", 2, firstKey)
	want.Certificate.Serial = "0a1b2c3d"
	want.Certificate.FingerprintSHA256 = "b4c1d2e3f40516273849a5b6c7d8e9f00112233445566778899aabbccddeeff0"
	if installation.ID() != "5f0b6a1e-3c2d-4b8f-9a7e-1d2c3b4a5f6e" || installation.Created() || !ok || !equal(enrolled, want) {
		t.Fatalf("read %s enrolled as %+v (%t), want %+v", installation.ID(), enrolled, ok, want)
	}
}

func TestOneInstallationComesOutOfConcurrentStarts(t *testing.T) {
	directory := stateDirectory(t)
	var installed string
	for _, round := range []string{"a new directory", "an existing installation"} {
		children := make([]*agent, 8)
		for index := range children {
			children[index] = start(t, directory)
		}
		for _, started := range children {
			started.send(t, "open")
		}
		var opened []string
		for _, started := range children {
			switch result := started.result(t); {
			case result == "locked":
			case strings.HasPrefix(result, "opened "):
				opened = append(opened, result)
			default:
				t.Fatalf("%s: a child reported %q", round, result)
			}
		}
		for _, started := range children {
			started.release(t)
		}
		for _, started := range children {
			started.wait(t)
		}
		if len(opened) != 1 {
			t.Fatalf("%s: %d children opened the installation: %q", round, len(opened), opened)
		}
		fields := strings.Fields(opened[0])
		if installed == "" {
			installed = fields[1]
		}
		if fields[1] != installed || fields[2] != fmt.Sprint(round == "a new directory") {
			t.Fatalf("%s: a child %s, and the installation is %s", round, opened[0], installed)
		}
	}
}

func TestAnAgentKilledWhileHoldingItsInstallationLeavesItUsable(t *testing.T) {
	directory := stateDirectory(t)
	holder := start(t, directory)
	holder.send(t, "open")
	opened := strings.Fields(holder.result(t))
	if len(opened) != 3 || opened[0] != "opened" {
		t.Fatalf("the child reported %q", opened)
	}
	holder.kill(t)

	installation := open(t, directory)
	if installation.ID() != opened[1] || installation.Created() {
		t.Fatalf("after the kill the installation is %s (created: %t), it was %s", installation.ID(), installation.Created(), opened[1])
	}
}

func TestASecondHolderIsRefusedUntilTheFirstLetsGo(t *testing.T) {
	directory := stateDirectory(t)
	holder := open(t, directory)
	if _, err := identity.Open(directory); !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("a second open while the first holds %s returned %v", directory, err)
	}
	if _, err := identity.Replace(directory); !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("a replacement while the agent holds %s returned %v", directory, err)
	}
	if err := holder.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	open(t, directory)
}

func TestDamagedStateIsRefusedAndLeftAsItWas(t *testing.T) {
	cases := map[string]string{
		"an empty file":                   "",
		"a truncated file":                enrolledState[:len(enrolledState)/2],
		"something other than JSON":       "\x00\x01\x02",
		"two documents":                   enrolledState + enrolledState,
		"a private key":                   strings.Replace(enrolledState, `"format": 1,`, `"format": 1, "private_key_pem": "-----BEGIN PRIVATE KEY-----",`, 1),
		"no format":                       strings.Replace(enrolledState, `"format": 1,`, ``, 1),
		"an identifier that is not drawn": strings.Replace(enrolledState, `5f0b6a1e-3c2d-4b8f`, `5f0b6a1e-3c2d-1b8f`, 1),
		"an identifier in upper case":     strings.Replace(enrolledState, `5f0b6a1e-3c2d-4b8f`, `5F0B6A1E-3C2D-4B8F`, 1),
		"no creation time":                strings.Replace(enrolledState, `"created_at": "2026-09-16T17:00:00Z",`, ``, 1),
		"an installation replacing itself": strings.Replace(enrolledState, `"format": 1,`,
			`"format": 1, "replaces": "5f0b6a1e-3c2d-4b8f-9a7e-1d2c3b4a5f6e",`, 1),
		"generation zero":                          strings.Replace(enrolledState, `"generation": 2`, `"generation": 0`, 1),
		"an agent the platform cannot name":        strings.Replace(enrolledState, `"agent_id": "web-01"`, `"agent_id": "web 01"`, 1),
		"a certificate for another agent":          strings.Replace(enrolledState, `"subject": "web-01"`, `"subject": "db-07"`, 1),
		"a key identifier that is not a digest":    strings.Replace(enrolledState, firstKey, "not-a-digest", 1),
		"a serial of half a byte":                  strings.Replace(enrolledState, `"0a1b2c3d"`, `"a1b2c3d"`, 1),
		"a fingerprint of the wrong length":        strings.Replace(enrolledState, `"b4c1d2e3f40516273849`, `"b4c1d2e3f4051627384`, 1),
		"a certificate that ends before it starts": strings.Replace(enrolledState, `"2026-11-30T00:00:00Z"`, `"2026-08-30T00:00:00Z"`, 1),
		"a file too large to be one":               enrolledState + strings.Repeat(" ", 64<<10),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			writeState(t, directory, content)
			for attempt := range 2 {
				if _, err := identity.Open(directory); !errors.Is(err, identity.ErrDamaged) {
					t.Fatalf("open %d returned %v", attempt+1, err)
				}
			}
			if kept := readState(t, directory); kept != content {
				t.Fatalf("the damaged state was rewritten as %q", kept)
			}
		})
	}
}

func TestStateThatIsNotAFileIsDamaged(t *testing.T) {
	for name, prepare := range map[string]func(directory string) error{
		"a directory": func(directory string) error {
			return os.Mkdir(filepath.Join(directory, "installation.json"), 0o700)
		},
		"a symbolic link": func(directory string) error {
			if err := os.WriteFile(filepath.Join(directory, "elsewhere.json"), []byte(enrolledState), 0o600); err != nil {
				return err
			}
			return os.Symlink("elsewhere.json", filepath.Join(directory, "installation.json"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("create %s: %v", directory, err)
			}
			if err := prepare(directory); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			if _, err := identity.Open(directory); !errors.Is(err, identity.ErrDamaged) {
				t.Fatalf("open returned %v", err)
			}
		})
	}
}

func TestADirectoryHoldingSomethingButNoInstallationIsDamaged(t *testing.T) {
	for name, entry := range map[string]func(directory string) error{
		"the installations it replaced": func(directory string) error { return os.Mkdir(filepath.Join(directory, "replaced"), 0o700) },
		"a key":                         func(directory string) error { return os.WriteFile(filepath.Join(directory, "key.pem"), nil, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("create %s: %v", directory, err)
			}
			if err := entry(directory); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			if _, err := identity.Open(directory); !errors.Is(err, identity.ErrDamaged) {
				t.Fatalf("open returned %v", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, "installation.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("an installation was created in its place: %v", err)
			}
		})
	}
}

func TestStateFromANewerAgentIsRefusedAndLeftAsItWas(t *testing.T) {
	directory := stateDirectory(t)
	newer := strings.Replace(enrolledState, `"format": 1,`, `"format": 2, "attestation": {"quote": "AAAA"},`, 1)
	writeState(t, directory, newer)

	_, err := identity.Open(directory)
	if !errors.Is(err, identity.ErrNewer) || errors.Is(err, identity.ErrDamaged) {
		t.Fatalf("open returned %v", err)
	}
	if kept := readState(t, directory); kept != newer {
		t.Fatalf("the newer state was rewritten as %q", kept)
	}
}

func TestStateOthersCanReachIsRefused(t *testing.T) {
	for name, prepare := range map[string]func(directory string) error{
		"a directory its group can list": func(directory string) error { return os.Chmod(directory, 0o750) },
		"a state anybody can read": func(directory string) error {
			return os.Chmod(filepath.Join(directory, "installation.json"), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			writeState(t, directory, enrolledState)
			if err := prepare(directory); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			if _, err := identity.Open(directory); !errors.Is(err, identity.ErrInsecure) {
				t.Fatalf("open returned %v", err)
			}
		})
	}

	t.Run("a directory that is a symbolic link", func(t *testing.T) {
		directory := stateDirectory(t)
		writeState(t, directory, enrolledState)
		linked := filepath.Join(t.TempDir(), "linked")
		if err := os.Symlink(directory, linked); err != nil {
			t.Fatalf("link %s: %v", directory, err)
		}
		if _, err := identity.Open(linked); !errors.Is(err, identity.ErrInsecure) {
			t.Fatalf("open returned %v", err)
		}
	})
}

func TestTheLeftoversOfAnInterruptedWriteAreDiscarded(t *testing.T) {
	leftover := ".installation.json.0123456789abcdef.tmp"
	for name, written := range map[string]bool{"before the first write": false, "after an earlier write": true} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			if written {
				writeState(t, directory, enrolledState)
			} else if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("create %s: %v", directory, err)
			}
			if err := os.WriteFile(filepath.Join(directory, leftover), []byte(`{"format": 1, "install`), 0o600); err != nil {
				t.Fatalf("leave an interrupted write: %v", err)
			}

			installation := open(t, directory)
			if installation.Created() == written {
				t.Fatalf("opened %s, created: %t", installation.ID(), installation.Created())
			}
			if _, err := os.Lstat(filepath.Join(directory, leftover)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the interrupted write is still there: %v", err)
			}
		})
	}
}

func TestActivationRecordsEveryCredentialGeneration(t *testing.T) {
	directory := stateDirectory(t)
	installation := open(t, directory)
	for _, next := range []identity.Enrollment{
		enrollment("web-01", 1, firstKey),
		enrollment("web-01", 2, firstKey),
		enrollment("web-01", 3, secondKey),
	} {
		if err := installation.Activate(next); err != nil {
			t.Fatalf("activate generation %d: %v", next.Generation, err)
		}
		if err := installation.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		installation = open(t, directory)
		if active, ok := installation.Enrollment(); !ok || !equal(active, next) {
			t.Fatalf("after a restart the active generation is %+v (%t), want %+v", active, ok, next)
		}
	}
}

func TestActivationRefusesToRelabelTheInstallationOrSkipAGeneration(t *testing.T) {
	directory := stateDirectory(t)
	installation := open(t, directory)
	wrongSubject := enrollment("web-01", 1, firstKey)
	wrongSubject.Certificate.Subject = "db-07"
	for name, next := range map[string]identity.Enrollment{
		"a first generation that is not 1":      enrollment("web-01", 2, firstKey),
		"a certificate issued to another agent": wrongSubject,
	} {
		if err := installation.Activate(next); !errors.Is(err, identity.ErrRefused) {
			t.Errorf("%s: activation returned %v", name, err)
		}
	}

	active := enrollment("web-01", 1, firstKey)
	if err := installation.Activate(active); err != nil {
		t.Fatalf("activate: %v", err)
	}
	for name, next := range map[string]identity.Enrollment{
		"another agent":               enrollment("db-07", 2, secondKey),
		"the active generation again": enrollment("web-01", 1, secondKey),
		"a generation that skips one": enrollment("web-01", 3, secondKey),
		"a key that is not a digest":  enrollment("web-01", 2, "0123"),
	} {
		if err := installation.Activate(next); !errors.Is(err, identity.ErrRefused) {
			t.Errorf("%s: activation returned %v", name, err)
		}
	}
	if err := installation.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if kept, ok := open(t, directory).Enrollment(); !ok || !equal(kept, active) {
		t.Fatalf("a refused activation left %+v (%t) active, want %+v", kept, ok, active)
	}
}

func TestReplacementStartsANewInstallationAndKeepsThePreviousOne(t *testing.T) {
	directory := stateDirectory(t)
	previous := open(t, directory)
	if err := previous.Activate(enrollment("web-01", 1, firstKey)); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := previous.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	previousState := readState(t, directory)

	replacement, err := identity.Replace(directory)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if !randomUUID.MatchString(replacement.ID()) || replacement.ID() == previous.ID() ||
		replacement.Replaces() != previous.ID() || !replacement.Created() {
		t.Fatalf("replaced %s with %s, which replaces %q (created: %t)",
			previous.ID(), replacement.ID(), replacement.Replaces(), replacement.Created())
	}
	if enrolled, ok := replacement.Enrollment(); ok {
		t.Fatalf("the replacement carries over the enrollment %+v", enrolled)
	}
	if kept := keptStates(t, directory); len(kept) != 1 || kept[0] != previousState {
		t.Fatalf("kept %q, want the previous state", kept)
	}
	if err := replacement.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := open(t, directory)
	if reopened.ID() != replacement.ID() || reopened.Replaces() != previous.ID() {
		t.Fatalf("after a restart the installation is %s replacing %q", reopened.ID(), reopened.Replaces())
	}
}

func TestReplacementRecoversFromStateThisAgentCannotRead(t *testing.T) {
	for name, content := range map[string]string{
		"damaged state":            enrolledState[:40],
		"state from a newer agent": strings.Replace(enrolledState, `"format": 1,`, `"format": 2,`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			writeState(t, directory, content)

			replacement, err := identity.Replace(directory)
			if err != nil {
				t.Fatalf("replace: %v", err)
			}
			defer replacement.Close()
			if !randomUUID.MatchString(replacement.ID()) || replacement.Replaces() != "" {
				t.Fatalf("replaced it with %s, which replaces %q", replacement.ID(), replacement.Replaces())
			}
			if kept := keptStates(t, directory); len(kept) != 1 || kept[0] != content {
				t.Fatalf("kept %q, want the state it replaced", kept)
			}
		})
	}
}

func TestReplacementNeedsAnInstallationToReplace(t *testing.T) {
	for name, prepare := range map[string]func(directory string) error{
		"a directory that does not exist": func(string) error { return nil },
		"an empty directory":              func(directory string) error { return os.Mkdir(directory, 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			directory := stateDirectory(t)
			if err := prepare(directory); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			if _, err := identity.Replace(directory); !errors.Is(err, identity.ErrNoInstallation) {
				t.Fatalf("replacing nothing returned %v", err)
			}
			if entries, err := os.ReadDir(directory); len(entries) != 0 || (err != nil && !errors.Is(err, os.ErrNotExist)) {
				t.Fatalf("replacing nothing left %v behind: %v", entries, err)
			}
		})
	}
}

func TestAReplacementInterruptedBeforeItsNewStateLeavesThePreviousInstallation(t *testing.T) {
	directory := stateDirectory(t)
	previous := open(t, directory)
	if err := previous.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.Mkdir(filepath.Join(directory, "replaced"), 0o700); err != nil {
		t.Fatalf("create the replaced directory: %v", err)
	}
	kept := filepath.Join(directory, "replaced", "20260916T170000.000000000Z.json")
	if err := os.Link(filepath.Join(directory, "installation.json"), kept); err != nil {
		t.Fatalf("keep the previous state: %v", err)
	}

	if reopened := open(t, directory); reopened.ID() != previous.ID() || reopened.Created() {
		t.Fatalf("the interrupted replacement left %s (created: %t), the installation is %s",
			reopened.ID(), reopened.Created(), previous.ID())
	}
}

type agent struct {
	process *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

func start(t *testing.T, directory string) *agent {
	t.Helper()
	process := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	process.Env = append(os.Environ(), childDirectory+"="+directory)
	input, err := process.StdinPipe()
	if err != nil {
		t.Fatalf("attach to the child's input: %v", err)
	}
	output, err := process.StdoutPipe()
	if err != nil {
		t.Fatalf("attach to the child's output: %v", err)
	}
	if err := process.Start(); err != nil {
		t.Fatalf("start a child: %v", err)
	}
	started := &agent{process: process, input: input, output: bufio.NewScanner(output)}
	t.Cleanup(func() {
		_ = started.input.Close()
		_ = started.process.Wait()
	})
	return started
}

func (a *agent) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(a.input, line+"\n"); err != nil {
		t.Fatalf("tell the child to %s: %v", line, err)
	}
}

func (a *agent) result(t *testing.T) string {
	t.Helper()
	read := make(chan bool, 1)
	go func() { read <- a.output.Scan() }()
	select {
	case scanned := <-read:
		if !scanned {
			t.Fatalf("the child ended before it reported: %v", a.output.Err())
		}
		return a.output.Text()
	case <-time.After(10 * time.Second):
		t.Fatal("the child reported nothing within 10s")
		return ""
	}
}

func (a *agent) release(t *testing.T) {
	t.Helper()
	if err := a.input.Close(); err != nil {
		t.Fatalf("release the child: %v", err)
	}
}

func (a *agent) wait(t *testing.T) {
	t.Helper()
	if err := a.process.Wait(); err != nil {
		t.Fatalf("the child exited with %v", err)
	}
}

func (a *agent) kill(t *testing.T) {
	t.Helper()
	if err := a.process.Process.Kill(); err != nil {
		t.Fatalf("kill the child: %v", err)
	}
	_ = a.process.Wait()
}

func stateDirectory(t *testing.T) string {
	return filepath.Join(t.TempDir(), "state")
}

func open(t *testing.T, directory string) *identity.Installation {
	t.Helper()
	installation, err := identity.Open(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { _ = installation.Close() })
	return installation
}

func writeState(t *testing.T, directory, content string) {
	t.Helper()
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatalf("create %s: %v", directory, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "installation.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write the installation state: %v", err)
	}
}

func readState(t *testing.T, directory string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, "installation.json"))
	if err != nil {
		t.Fatalf("read the installation state: %v", err)
	}
	return string(content)
}

func keptStates(t *testing.T, directory string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "replaced", "*.json"))
	if err != nil {
		t.Fatalf("list the replaced states: %v", err)
	}
	var kept []string
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		kept = append(kept, string(content))
	}
	return kept
}

func enrollment(agentID string, generation uint64, key string) identity.Enrollment {
	return identity.Enrollment{
		AgentID:    agentID,
		Generation: generation,
		KeyID:      key,
		Certificate: identity.Certificate{
			Subject:           agentID,
			Serial:            fmt.Sprintf("%02x", generation),
			FingerprintSHA256: strings.Repeat(fmt.Sprintf("%02x", generation), 32),
			NotBefore:         time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:          time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC),
		},
	}
}

func equal(a, b identity.Enrollment) bool {
	return a.AgentID == b.AgentID && a.Generation == b.Generation && a.KeyID == b.KeyID &&
		a.Certificate.Subject == b.Certificate.Subject && a.Certificate.Serial == b.Certificate.Serial &&
		a.Certificate.FingerprintSHA256 == b.Certificate.FingerprintSHA256 &&
		a.Certificate.NotBefore.Equal(b.Certificate.NotBefore) && a.Certificate.NotAfter.Equal(b.Certificate.NotAfter)
}
