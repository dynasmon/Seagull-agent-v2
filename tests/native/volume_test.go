//go:build linux

package native_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A filesystem of its own for the installation: an ext4 image the gate attaches
// to a loop device and mounts where the package keeps the state, as a host
// whose kernel makes a filesystem read-only once it finds an error in it, then
// has the watch on what the agent stages watch the filesystem it mounted. The
// gate fills it, has the kernel find an error in it and repairs it as an
// operator does, and never touches the filesystems of the host.
type volume struct {
	image   string
	device  string
	mounted string
	uid     int
	gid     int
	fillers []string
}

func mountVolume(t *testing.T, scratch, mounted string, size int64, uid, gid int) *volume {
	t.Helper()
	image := filepath.Join(scratch, "state.img")
	if err := os.WriteFile(image, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(image, size); err != nil {
		t.Fatal(err)
	}
	run(t, "mkfs.ext4", "-q", "-F", "-m", "1", image)
	v := &volume{image: image, device: attach(t, image), mounted: mounted, uid: uid, gid: gid}
	v.mount(t)
	return v
}

func (v *volume) release() {
	exec.Command("umount", v.mounted).Run()
	exec.Command("losetup", "--detach", v.device).Run()
}

// A container sees the loop devices that existed when it started, so the gate
// creates the node of the free one the kernel names when it is missing.
func attach(t *testing.T, image string) string {
	t.Helper()
	device := run(t, "losetup", "--find")
	if _, err := os.Stat(device); errors.Is(err, fs.ErrNotExist) {
		minor, err := strconv.Atoi(strings.TrimPrefix(device, "/dev/loop"))
		if err != nil {
			t.Fatalf("losetup named %q as the free loop device", device)
		}
		if err := syscall.Mknod(device, syscall.S_IFBLK|0o660, 7<<8|minor); err != nil {
			t.Fatalf("create %s: %v", device, err)
		}
	}
	run(t, "losetup", device, image)
	return device
}

func (v *volume) mount(t *testing.T) {
	t.Helper()
	run(t, "mount", "-o", "errors=remount-ro,nosuid,nodev", v.device, v.mounted)
	if err := os.Remove(filepath.Join(v.mounted, "lost+found")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("e2fsck found what it could not place back in the installation, and kept it in lost+found: %v\n%s", err, answer("ls", "-laR", filepath.Join(v.mounted, "lost+found")))
	}
	if err := errors.Join(os.Chown(v.mounted, v.uid, v.gid), os.Chmod(v.mounted, 0o700)); err != nil {
		t.Fatal(err)
	}
	run(t, "systemctl", "restart", watchUnit)
}

func (v *volume) free(t *testing.T) int64 {
	t.Helper()
	var held syscall.Statfs_t
	if err := syscall.Statfs(v.mounted, &held); err != nil {
		t.Fatalf("inspect %s: %v", v.mounted, err)
	}
	return int64(held.Bavail) * held.Bsize
}

func (v *volume) fill(t *testing.T, leave int64) {
	t.Helper()
	filler := filepath.Join(v.mounted, fmt.Sprintf(".filler-%d", len(v.fillers)))
	if leave == 0 {
		filled := exec.Command("dd", "if=/dev/zero", "of="+filler, "bs=1M")
		filled.Env = append(os.Environ(), "LC_ALL=C")
		said, err := filled.CombinedOutput()
		v.fillers = append(v.fillers, filler)
		if available := v.free(t); err == nil || !strings.Contains(string(said), "No space left on device") || available != 0 {
			t.Fatalf("fill %s: %v, %d bytes left\n%s", v.mounted, err, available, said)
		}
		return
	}
	available := v.free(t)
	if available <= leave {
		return
	}
	run(t, "fallocate", "--length", strconv.FormatInt(available-leave, 10), filler)
	v.fillers = append(v.fillers, filler)
}

func (v *volume) empty(t *testing.T) {
	t.Helper()
	for _, filler := range v.fillers {
		if err := os.Remove(filler); err != nil {
			t.Fatal(err)
		}
	}
	v.fillers = nil
}

func (v *volume) fail(t *testing.T) {
	t.Helper()
	trigger := filepath.Join("/sys/fs/ext4", filepath.Base(v.device), "trigger_fs_error")
	if err := os.WriteFile(trigger, []byte("chaos\n"), 0); err != nil {
		t.Fatalf("have the kernel find an error in %s: %v", v.mounted, err)
	}
}

func (v *volume) repair(t *testing.T) {
	t.Helper()
	run(t, "umount", v.mounted)
	checked := exec.Command("e2fsck", "-f", "-y", v.device)
	if said, err := checked.CombinedOutput(); err != nil && checked.ProcessState.ExitCode() != 1 {
		t.Fatalf("e2fsck %s: %v\n%s", v.device, err, said)
	}
	v.mount(t)
}

func (c *chaos) full(t *testing.T) {
	writing := c.write(t, "full", 900, 50*time.Millisecond)
	time.Sleep(3 * time.Second)
	began := time.Now()
	c.volume.fill(t, 48<<20)
	c.logged(t, "spool_admission_paused", began, 30*time.Second)
	c.says(t, "for room in the spool, while what sshd decides waits in the journal", 45*time.Second)
	c.volume.fill(t, 0)
	time.Sleep(5 * time.Second)
	c.volume.empty(t)
	c.logged(t, "spool_admission_resumed", began, time.Minute)
	writing.wait(t)
	c.settled(t, 2*time.Minute)
}

func (c *chaos) readOnly(t *testing.T) {
	writing := c.write(t, "readonly", 900, 50*time.Millisecond)
	time.Sleep(3 * time.Second)
	broken, began := c.invocation, time.Now()
	c.volume.fail(t)
	stopped := await(t, broken, "agent_stopped", 30*time.Second)
	if stopped["level"] != "ERROR" || !strings.Contains(fmt.Sprint(stopped["error"]), "can no longer make records durable") {
		t.Errorf("the agent whose filesystem turned read-only stopped with %v", stopped)
	}
	refused := c.unstarted(t, began, time.Minute)
	if !strings.Contains(fmt.Sprint(refused["recovery"]), "read-only") {
		t.Errorf("on a read-only filesystem the agent did not start and said %v", refused)
	}
	run(t, "systemctl", "stop", unit)
	writing.wait(t)
	c.volume.repair(t)
	run(t, "systemctl", "start", unit)
	c.invocation = started(t, broken)
	c.settled(t, 2*time.Minute)
}

// Records stay in the spool while the platform takes nothing, and the gate
// damages the payload of one of them on disk with the agent stopped: the one
// record is lost, counted as lost, and every other one is delivered.
func (c *chaos) damage(t *testing.T) {
	c.mode.Store(unavailable)
	c.write(t, "damage", 40, 20*time.Millisecond).wait(t)
	victim := "damage-000020"
	deadline := time.Now().Add(time.Minute)
	for !c.spooled(t, "damage-000001", "damage-000040", victim) {
		if time.Now().After(deadline) {
			t.Fatal("the spool did not hold what sshd decided within a minute")
		}
		time.Sleep(250 * time.Millisecond)
	}
	run(t, "systemctl", "stop", unit)
	segments, err := filepath.Glob(filepath.Join(state, "spool", "events", "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	damaged := 0
	for _, segment := range segments {
		content, err := os.ReadFile(segment)
		if err != nil {
			t.Fatal(err)
		}
		if at := bytes.Index(content, []byte(victim)); at >= 0 {
			if bytes.Count(content, []byte(victim)) != 2 {
				t.Fatalf("%s holds the outcome of %s %d times, and one record names it twice", segment, victim, bytes.Count(content, []byte(victim)))
			}
			content[at] ^= 0x20
			if err := os.WriteFile(segment, content, 0o600); err != nil {
				t.Fatal(err)
			}
			damaged++
		}
	}
	if damaged != 1 {
		t.Fatalf("the outcome of %s is in %d segments", victim, damaged)
	}
	c.fated(victim, lost)
	run(t, "systemctl", "start", unit)
	c.invocation = started(t, c.invocation)
	c.mode.Store(answering)
	c.settled(t, 2*time.Minute)
	if found := c.logged(t, "spool_records_lost", time.Time{}, 30*time.Second); found["records"] != float64(1) || found["stream"] != "events" {
		t.Errorf("the agent reported the damaged record as %v", found)
	}
}

func (c *chaos) spooled(t *testing.T, users ...string) bool {
	t.Helper()
	segments, err := filepath.Glob(filepath.Join(state, "spool", "events", "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	var held []byte
	for _, segment := range segments {
		content, err := os.ReadFile(segment)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		held = append(held, content...)
	}
	for _, user := range users {
		if !bytes.Contains(held, []byte(user)) {
			return false
		}
	}
	return true
}
