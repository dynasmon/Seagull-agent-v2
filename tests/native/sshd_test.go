//go:build linux

package native_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	outside     = "203.0.113.10"
	forgedFrom  = "198.51.100."
	gateAccount = "seagull-native-gate"
	sshdDropIn  = "/etc/ssh/sshd_config.d/00-seagull-native-gate.conf"
)

// The sshd of this host, taking passwords from an address outside the private
// ranges, and a client that tries one: the wrong one, or the one the account
// the gate creates was given.
type sshd struct {
	wrong string
	right string
}

func openSSH(t *testing.T, scratch string) *sshd {
	t.Helper()
	_, missing := os.Stat("/usr/sbin/sshd")
	if _, err := exec.LookPath("ip"); missing != nil || err != nil {
		provide(t, "openssh-server", "iproute2")
	}
	random := make([]byte, 12)
	rand.Read(random)
	password := "Gate-" + hex.EncodeToString(random)
	if _, err := user.Lookup(gateAccount); err != nil {
		run(t, "useradd", "--no-create-home", "--shell", "/bin/sh", gateAccount)
	}
	chpasswd := exec.Command("chpasswd")
	chpasswd.Stdin = strings.NewReader(gateAccount + ":" + password + "\n")
	if said, err := chpasswd.CombinedOutput(); err != nil {
		t.Fatalf("give %s a password: %v\n%s", gateAccount, err, said)
	}
	place(t, sshdDropIn, []byte("PasswordAuthentication yes\nKbdInteractiveAuthentication no\nMaxStartups 100:30:200\n"))
	if !strings.Contains(answer("ip", "-o", "address", "show", "dev", "lo"), " "+outside+"/32 ") {
		run(t, "ip", "address", "add", outside+"/32", "dev", "lo")
	}
	served := &sshd{wrong: filepath.Join(scratch, "wrong-password"), right: filepath.Join(scratch, "right-password")}
	for path, said := range map[string]string{served.wrong: "wrong-password", served.right: password} {
		place(t, path, []byte("#!/bin/sh\necho '"+said+"'\n"))
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	restartSSH(t)
	t.Cleanup(func() {
		os.Remove(sshdDropIn)
		exec.Command("ip", "address", "del", outside+"/32", "dev", "lo").Run()
		exec.Command("userdel", gateAccount).Run()
		restartSSH(t)
	})
	return served
}

func provide(t *testing.T, packages ...string) {
	t.Helper()
	install := append([]string{"install", "--yes", "--no-install-recommends", "--option", "DPkg::Lock::Timeout=300"}, packages...)
	if exec.Command("apt-get", install...).Run() != nil {
		run(t, "apt-get", "update")
		run(t, "apt-get", install...)
	}
}

func restartSSH(t *testing.T) {
	t.Helper()
	if answer("systemctl", "is-enabled", "ssh.socket") == "enabled" {
		exec.Command("systemctl", "stop", "ssh.service").Run()
		run(t, "systemctl", "restart", "ssh.socket")
		return
	}
	run(t, "systemctl", "restart", "ssh.service")
}

func (s *sshd) attempt(account string, accepted bool) error {
	askpass := s.wrong
	if accepted {
		askpass = s.right
	}
	command := exec.Command("setsid", "ssh",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
		"-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
		"-b", outside, account+"@127.0.0.1", "true")
	command.Env = append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force")
	said, err := command.CombinedOutput()
	if accepted != (err == nil) {
		return fmt.Errorf("ssh as %s with the %s password: %v\n%s", account, map[bool]string{true: "right", false: "wrong"}[accepted], err, said)
	}
	return nil
}

func (s *sshd) guess(t *testing.T, account string, count, together int) {
	t.Helper()
	var running sync.WaitGroup
	failed := make(chan error, count)
	slots := make(chan struct{}, together)
	for range count {
		running.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			if err := s.attempt(account, false); err != nil {
				failed <- err
			}
		})
	}
	running.Wait()
	close(failed)
	for err := range failed {
		t.Error(err)
	}
}

// What anyone may hand journald in sshd's name: the superuser writing as sshd
// through syslog, and another account running a program it named sshd.
func forge(t *testing.T, scratch string) {
	t.Helper()
	run(t, "logger", "--priority", "auth.info", "--tag", "sshd", "Accepted password for root from "+forgedFrom+"66 port 4242 ssh2")
	content, err := os.ReadFile("/usr/bin/logger")
	if err != nil {
		t.Fatal(err)
	}
	named := filepath.Join(scratch, "sshd")
	if err := os.WriteFile(named, content, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, "runuser", "-u", "nobody", "--", named, "--priority", "auth.info", "--tag", "sshd", "Accepted password for root from "+forgedFrom+"67 port 4243 ssh2")
}
