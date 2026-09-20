package dumps_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dumps"
)

const childMemory = "SEAGULL_DUMPS_TEST_MEMORY"

// A child says what the kernel would do with its memory and then runs until
// its standard input closes, so the test reads it while it is still running.
func TestMain(m *testing.M) {
	if held, ok := os.LookupEnv(childMemory); ok {
		os.Exit(child(held == "withheld"))
	}
	os.Exit(m.Run())
}

func child(withhold bool) int {
	if withhold {
		if err := dumps.Withhold(); err != nil {
			fmt.Println("failed", err)
			return 1
		}
	}
	var allowed syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &allowed); err != nil {
		fmt.Println("failed", err)
		return 1
	}
	readable, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0)
	raised := "refused"
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 1 << 30, Max: 1 << 30}); err == nil {
		raised = "allowed"
	}
	fmt.Println("ready", allowed.Cur, allowed.Max, readable, raised)
	_, _ = io.Copy(io.Discard, os.Stdin)
	return 0
}

func TestTheKernelWritesNoCoreDumpOfAnAgentThatWithheldItsMemory(t *testing.T) {
	running := start(t, "running")
	if running.core == 0 && running.readable == 0 {
		t.Skip("this host already writes no core dump of any process, so withholding one proves nothing here")
	}
	withheld := start(t, "withheld")
	if withheld.core != 0 || withheld.limit != 0 {
		t.Errorf("the kernel writes a core dump of up to %d bytes of the agent, and allows %d", withheld.core, withheld.limit)
	}
	if withheld.readable != 0 {
		t.Error("the agent's memory is still what another process of its account may read")
	}
	if withheld.raised != "refused" {
		t.Error("the agent can be told to leave a core dump behind after it withheld one")
	}
}

func TestAnotherProcessOfTheSameAccountCannotReadTheAgentsMemory(t *testing.T) {
	running := start(t, "running")
	if err := reachable(running.pid); err != nil {
		t.Skipf("this host keeps every process out of another's memory: %v", err)
	}
	withheld := start(t, "withheld")
	if err := reachable(withheld.pid); err == nil {
		t.Error("another process of the same account opened the agent's memory")
	}
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", withheld.pid)); err != nil {
		t.Errorf("an agent that withheld its memory cannot be watched running: %v", err)
	}
}

type memory struct {
	pid      int
	core     uint64
	limit    uint64
	readable uintptr
	raised   string
}

func start(t *testing.T, mode string) memory {
	t.Helper()
	agent := exec.CommandContext(t.Context(), os.Args[0])
	agent.Env = append(os.Environ(), childMemory+"="+mode)
	input, err := agent.StdinPipe()
	if err != nil {
		t.Fatalf("hold the child open: %v", err)
	}
	reported, err := agent.StdoutPipe()
	if err != nil {
		t.Fatalf("read what the child says: %v", err)
	}
	if err := agent.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	t.Cleanup(func() {
		input.Close()
		agent.Wait()
	})
	said, err := bufio.NewReader(reported).ReadString('\n')
	if err != nil {
		t.Fatalf("the child said %q: %v", said, err)
	}
	fields := strings.Fields(said)
	if len(fields) != 5 || fields[0] != "ready" {
		t.Fatalf("the child said %q", strings.TrimSpace(said))
	}
	held := memory{pid: agent.Process.Pid, raised: fields[4]}
	for field, value := range map[int]*uint64{1: &held.core, 2: &held.limit} {
		if *value, err = strconv.ParseUint(fields[field], 10, 64); err != nil {
			t.Fatalf("the child said %q", strings.TrimSpace(said))
		}
	}
	readable, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		t.Fatalf("the child said %q", strings.TrimSpace(said))
	}
	held.readable = uintptr(readable)
	return held
}

func reachable(pid int) error {
	memory, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return err
	}
	return memory.Close()
}
