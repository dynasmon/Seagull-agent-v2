//go:build linux

package native_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	probeVariable = "SEAGULL_NATIVE_PROBE"
	probeHome     = "/usr/local/lib/seagull-native-gate"
	probeName     = "seagull-native-probe-"
	allowed       = "allowed"
	noCapability  = "0000000000000000"
)

// What the account the agent runs as may do, as the kernel answers a copy of
// this test that the service runs before the agent, confined as the agent is,
// or that the gate runs as the account outside the service. The probe reports
// and never judges, so the agent starts after it whatever it found.
type probed struct {
	Message  string            `json:"msg"`
	User     int               `json:"user"`
	Checks   map[string]string `json:"checks"`
	Mounts   map[string]string `json:"mounts"`
	Devices  []string          `json:"devices"`
	Writable []string          `json:"writable"`
}

var errnos = map[syscall.Errno]string{
	syscall.EPERM: "EPERM", syscall.EACCES: "EACCES", syscall.EROFS: "EROFS", syscall.ENOENT: "ENOENT",
	syscall.EAFNOSUPPORT: "EAFNOSUPPORT", syscall.ENOSYS: "ENOSYS", syscall.EINVAL: "EINVAL", syscall.ENOEXEC: "ENOEXEC",
}

var signals = map[syscall.Signal]string{syscall.SIGSYS: "SIGSYS", syscall.SIGSEGV: "SIGSEGV", syscall.SIGILL: "SIGILL"}

const (
	pidfdOpen  = 434
	pidfdGetfd = 438
)

func probe(marker string) int {
	mounts := mounted()
	found := probed{Message: "native_probe", User: os.Getuid(), Mounts: map[string]string{}, Checks: map[string]string{
		"write /run/lock":            create("/run/lock", marker, false),
		"write /dev/shm":             create("/dev/shm", marker, false),
		"write /dev/mqueue":          create("/dev/mqueue", marker, false),
		"write /tmp":                 create("/tmp", marker, true),
		"write /var/tmp":             create("/var/tmp", marker, true),
		"list /home":                 list("/home"),
		"list /run/user":             list("/run/user"),
		"list /usr/lib/modules":      list("/usr/lib/modules"),
		"see /proc/1":                see("/proc/1"),
		"unix socket":                socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0),
		"netlink socket":             socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE),
		"inet socket":                socket(syscall.AF_INET, syscall.SOCK_STREAM, 0),
		"inet6 socket":               socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0),
		"user namespace":             namespace(),
		"32-bit personality":         personality(),
		"writable executable memory": executable(),
		"setuid file":                setuid(marker),
		"real-time scheduling":       realtime(),
		"clock discipline":           clock(),
		"kernel log":                 kernelLog(),
		"pidfd_getfd on itself":      descriptor(),
		"setuid to its own uid":      ownUser(),
		"32-bit system call":         compat(marker),
	}}
	for _, path := range []string{"/", "/etc", "/usr", "/run", state, "/proc/sys", "/sys", "/sys/fs/cgroup"} {
		found.Mounts[path] = "ro"
		if mounts[containing(mounts, path)] {
			found.Mounts[path] = "rw"
		}
	}
	found.Devices = devices()
	found.Writable = writable(mounts)
	line, err := json.Marshal(found)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(string(line))
	return 0
}

func outcome(err error) string {
	var errno syscall.Errno
	switch {
	case err == nil:
		return allowed
	case errors.As(err, &errno):
		if name, named := errnos[errno]; named {
			return name
		}
		return "errno " + strconv.Itoa(int(errno))
	}
	return err.Error()
}

func create(directory, marker string, keep bool) string {
	path := filepath.Join(directory, probeName+marker)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return outcome(err)
	}
	file.Close()
	if !keep {
		os.Remove(path)
	}
	return allowed
}

func list(directory string) string {
	_, err := os.ReadDir(directory)
	return outcome(err)
}

func see(path string) string {
	_, err := os.Stat(path)
	return outcome(err)
}

func socket(family, kind, protocol int) string {
	descriptor, err := syscall.Socket(family, kind, protocol)
	if err != nil {
		return outcome(err)
	}
	syscall.Close(descriptor)
	return allowed
}

func namespace() string {
	command := exec.Command("/usr/bin/true")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	return outcome(command.Run())
}

func personality() string {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previous, _, errno := syscall.RawSyscall(syscall.SYS_PERSONALITY, 0x0008, 0, 0)
	if errno != 0 {
		return outcome(errno)
	}
	syscall.RawSyscall(syscall.SYS_PERSONALITY, previous, 0, 0)
	return allowed
}

func executable() string {
	mapped, err := syscall.Mmap(-1, 0, os.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return outcome(err)
	}
	syscall.Munmap(mapped)
	return allowed
}

func setuid(marker string) string {
	path := filepath.Join("/tmp", probeName+marker+"-setuid")
	if err := os.WriteFile(path, nil, 0o700); err != nil {
		return outcome(err)
	}
	defer os.Remove(path)
	return outcome(os.Chmod(path, 0o700|fs.ModeSetuid))
}

func realtime() string {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	parameter := struct{ priority int32 }{priority: 1}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETSCHEDULER, 0, 1, uintptr(unsafe.Pointer(&parameter))); errno != 0 {
		return outcome(errno)
	}
	parameter.priority = 0
	syscall.RawSyscall(syscall.SYS_SCHED_SETSCHEDULER, 0, 0, uintptr(unsafe.Pointer(&parameter)))
	return allowed
}

func clock() string {
	_, err := syscall.Adjtimex(&syscall.Timex{})
	return outcome(err)
}

func kernelLog() string {
	_, err := syscall.Klogctl(10, nil)
	return outcome(err)
}

func descriptor() string {
	process, _, errno := syscall.RawSyscall(pidfdOpen, uintptr(os.Getpid()), 0, 0)
	if errno != 0 {
		return "pidfd_open: " + outcome(errno)
	}
	defer syscall.Close(int(process))
	copied, _, errno := syscall.RawSyscall(pidfdGetfd, process, 0, 0)
	if errno != 0 {
		return outcome(errno)
	}
	syscall.Close(int(copied))
	return allowed
}

func ownUser() string {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(os.Getuid()), 0, 0); errno != 0 {
		return outcome(errno)
	}
	return allowed
}

func compat(marker string) string {
	path := filepath.Join("/tmp", probeName+marker+"-i386")
	if err := os.WriteFile(path, exits(42), 0o700); err != nil {
		return outcome(err)
	}
	defer os.Remove(path)
	err := exec.Command(path).Run()
	var exited *exec.ExitError
	if !errors.As(err, &exited) {
		return outcome(err)
	}
	if exited.ExitCode() == 42 {
		return allowed
	}
	if status, ok := exited.Sys().(syscall.WaitStatus); ok && status.Signaled() && signals[status.Signal()] != "" {
		return signals[status.Signal()]
	}
	return exited.String()
}

// A 32-bit x86 program of three instructions that asks the kernel to end it
// with code, through the system call gate 32-bit programs use, and halts.
func exits(code byte) []byte {
	const base = 0x08048000
	program := []byte{0xb8, 0x01, 0x00, 0x00, 0x00, 0xbb, code, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xf4}
	size := uint32(52 + 32 + len(program))
	var image bytes.Buffer
	image.Write([]byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.Write(&image, binary.LittleEndian, struct {
		Type, Machine                                         uint16
		Version, Entry, ProgramHeaders, Sections, Flags       uint32
		Size, ProgramHeaderSize, Programs, SectionSize, Count uint16
		Names                                                 uint16
	}{Type: 2, Machine: 3, Version: 1, Entry: base + 52 + 32, ProgramHeaders: 52, Size: 52, ProgramHeaderSize: 32, Programs: 1})
	binary.Write(&image, binary.LittleEndian, struct {
		Type, Offset, Address, Physical, File, Memory, Flags, Align uint32
	}{Type: 1, Address: base, Physical: base, File: size, Memory: size, Flags: 5, Align: 0x1000})
	image.Write(program)
	return image.Bytes()
}

func devices() []string {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return []string{outcome(err)}
	}
	var found []string
	for _, entry := range entries {
		switch kind := entry.Type(); {
		case kind&fs.ModeCharDevice != 0:
			found = append(found, entry.Name())
		case kind&fs.ModeDevice != 0:
			found = append(found, entry.Name()+" (block)")
		}
	}
	return found
}

func mounted() map[string]bool {
	mounts := map[string]bool{}
	content, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return mounts
	}
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			mounts[unescaped(fields[4])] = slices.Contains(strings.Split(fields[5], ","), "rw")
		}
	}
	return mounts
}

func unescaped(field string) string {
	var path strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+4 <= len(field) {
			if code, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				path.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		path.WriteByte(field[i])
	}
	return path.String()
}

func containing(mounts map[string]bool, path string) string {
	found := "/"
	for point := range mounts {
		if (path == point || strings.HasPrefix(path, strings.TrimSuffix(point, "/")+"/")) && len(point) > len(found) {
			found = point
		}
	}
	return found
}

// Every directory and file the account may write, on the mounts that are not
// read-only, outside /proc, which holds the probe's own process. A root the
// account may write is reported as itself, since walking all of it would say
// little more and cost far more.
func writable(mounts map[string]bool) []string {
	if mounts["/"] {
		return []string{"/"}
	}
	var found []string
	for _, point := range slices.Sorted(maps.Keys(mounts)) {
		if !mounts[point] || point == "/proc" || strings.HasPrefix(point, "/proc/") {
			continue
		}
		filepath.WalkDir(point, func(path string, entry fs.DirEntry, err error) error {
			_, mount := mounts[path]
			switch {
			case err != nil:
				return nil
			case path != point && mount && entry.IsDir():
				return filepath.SkipDir
			case path != point && mount, !entry.IsDir() && !entry.Type().IsRegular(), syscall.Access(path, 2) != nil:
				return nil
			}
			found = append(found, path)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
	}
	slices.Sort(found)
	return found
}

func (g *gate) confine(t *testing.T) {
	installed := filepath.Join(probeHome, "native.test")
	if err := os.MkdirAll(probeHome, 0o755); err != nil {
		t.Fatalf("create %s: %v", probeHome, err)
	}
	t.Cleanup(func() { os.RemoveAll(probeHome) })
	copySelf(t, installed)
	marker := strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.MkdirAll(overrides, 0o755); err != nil {
		t.Fatalf("create %s: %v", overrides, err)
	}
	dropIn := filepath.Join(overrides, "probe.conf")
	place(t, dropIn, fmt.Appendf(nil, "[Service]\nExecStartPre=/usr/bin/env %s=confined-%s %s\n", probeVariable, marker, installed))
	run(t, "systemctl", "daemon-reload")
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)
	confined := decoded(t, await(t, g.invocation, "native_probe", 10*time.Second))
	if err := os.Remove(dropIn); err != nil {
		t.Fatalf("remove %s: %v", dropIn, err)
	}
	run(t, "systemctl", "daemon-reload")
	free := g.unconfined(t, installed, "free-"+marker)
	if confined.User != g.uid || free.User != g.uid {
		t.Fatalf("the probe ran as uid %d in the service and %d outside it, and the account is %d", confined.User, free.User, g.uid)
	}

	for check, want := range map[string]struct{ confined, free string }{
		"write /run/lock":            {"EROFS", allowed},
		"write /dev/shm":             {"EACCES", allowed},
		"write /dev/mqueue":          {"EACCES", allowed},
		"write /tmp":                 {allowed, allowed},
		"write /var/tmp":             {allowed, allowed},
		"list /home":                 {"EACCES", allowed},
		"list /run/user":             {"EACCES", allowed},
		"see /proc/1":                {"ENOENT", allowed},
		"unix socket":                {"EAFNOSUPPORT", allowed},
		"netlink socket":             {"EAFNOSUPPORT", allowed},
		"inet socket":                {allowed, allowed},
		"inet6 socket":               {allowed, allowed},
		"32-bit personality":         {"EPERM", allowed},
		"writable executable memory": {"EPERM|EACCES", allowed},
		"setuid file":                {"EPERM", allowed},
		"clock discipline":           {"EPERM", allowed},
		"pidfd_getfd on itself":      {"EPERM", allowed},
		"setuid to its own uid":      {"EPERM", allowed},
		"32-bit system call":         {"SIGSYS", allowed},
		"user namespace":             {confined: "EPERM"},
		"real-time scheduling":       {confined: "EPERM"},
		"kernel log":                 {confined: "EPERM"},
	} {
		if !slices.Contains(strings.Split(want.confined, "|"), confined.Checks[check]) {
			t.Errorf("in the service the agent's account is answered %q to %s, want %q", confined.Checks[check], check, want.confined)
		}
		if want.free != "" && free.Checks[check] != want.free {
			t.Errorf("outside the service the account is answered %q to %s, want %q: the gate cannot show what the service takes away", free.Checks[check], check, want.free)
		}
	}
	if modules := confined.Checks["list /usr/lib/modules"]; modules == allowed || (free.Checks["list /usr/lib/modules"] == allowed && modules != "EACCES") {
		t.Errorf("in the service the agent's account lists the kernel's modules as %q, and outside it as %q", modules, free.Checks["list /usr/lib/modules"])
	}
	for path, want := range map[string]string{"/": "ro", "/etc": "ro", "/usr": "ro", "/run": "ro", "/proc/sys": "ro", "/sys": "ro", "/sys/fs/cgroup": "ro", state: "rw"} {
		if confined.Mounts[path] != want {
			t.Errorf("in the service %s is mounted %s, want %s", path, confined.Mounts[path], want)
		}
	}
	for _, path := range []string{"/", "/run", "/proc/sys", "/sys", "/sys/fs/cgroup"} {
		if free.Mounts[path] != "rw" {
			t.Errorf("outside the service %s is mounted %s, so the gate cannot show the service making it read-only", path, free.Mounts[path])
		}
	}
	if want := []string{"/tmp", state, "/var/tmp"}; !slices.Equal(confined.Writable, want) || !slices.Equal(free.Writable, []string{"/"}) {
		t.Errorf("in the service the agent's account may write %q, and outside it %q; its installation and its own temporary directories alone are wanted", confined.Writable, free.Writable)
	}
	for _, device := range confined.Devices {
		if !slices.Contains([]string{"full", "null", "random", "tty", "urandom", "zero"}, device) {
			t.Errorf("in the service the agent's account finds the device %s, among %q", device, confined.Devices)
		}
	}
	if len(free.Devices) <= len(confined.Devices) {
		t.Errorf("outside the service the account finds the devices %q, and in it %q", free.Devices, confined.Devices)
	}
	for _, directory := range []string{"/tmp", "/var/tmp"} {
		if _, err := os.Lstat(filepath.Join(directory, probeName+"confined-"+marker)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("what the agent's account wrote to %s in the service is in the host's: %v", directory, err)
		}
		left := filepath.Join(directory, probeName+"free-"+marker)
		if _, err := os.Lstat(left); err != nil {
			t.Errorf("what the account wrote to %s outside the service is not in the host's: %v", directory, err)
		}
		os.Remove(left)
	}

	pid := property(t, "MainPID")
	content, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		t.Fatalf("read the status of the agent: %v", err)
	}
	reported := map[string]string{}
	for line := range strings.Lines(string(content)) {
		name, value, _ := strings.Cut(line, ":")
		reported[name] = strings.TrimSpace(value)
	}
	for name, want := range map[string]string{"NoNewPrivs": "1", "Seccomp": "2", "CapInh": noCapability, "CapPrm": noCapability, "CapEff": noCapability, "CapBnd": noCapability, "CapAmb": noCapability} {
		if reported[name] != want {
			t.Errorf("the agent runs with %s %q, want %q", name, reported[name], want)
		}
	}
	for _, kind := range []string{"mnt", "uts", "ipc"} {
		agent, err := os.Readlink(filepath.Join("/proc", pid, "ns", kind))
		host, hostErr := os.Readlink(filepath.Join("/proc/1/ns", kind))
		if err != nil || hostErr != nil || agent == host {
			t.Errorf("the agent runs in the %s namespace %s and the host in %s (%v, %v)", kind, agent, host, err, hostErr)
		}
	}
	agent := await(t, g.invocation, "agent_starting", time.Second)
	if agent["installation_id"] != g.installation || agent["credential_generation"] != float64(1) {
		t.Errorf("the confined service started the agent as %v", agent)
	}
}

func (g *gate) unconfined(t *testing.T, installed, marker string) probed {
	t.Helper()
	command := exec.Command("runuser", "-u", account, "--", "/usr/bin/env", probeVariable+"="+marker, installed)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	said, err := command.Output()
	if err != nil {
		t.Fatalf("probe as %s outside the service: %v\n%s", account, err, stderr.String())
	}
	var found probed
	if err := json.Unmarshal(said, &found); err != nil {
		t.Fatalf("read what the probe found outside the service, %q: %v", said, err)
	}
	return found
}

func decoded(t *testing.T, entry map[string]any) probed {
	t.Helper()
	var found probed
	content, err := json.Marshal(entry)
	if err == nil {
		err = json.Unmarshal(content, &found)
	}
	if err != nil {
		t.Fatalf("read what the probe found in the service: %v", err)
	}
	return found
}
