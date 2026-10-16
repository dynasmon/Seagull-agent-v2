package sysctl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func kernel(t *testing.T, parameters map[string]string) {
	t.Helper()
	held := t.TempDir()
	for path, value := range parameters {
		full := filepath.Join(held, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previous := root
	root = held
	t.Cleanup(func() { root = previous })
}

func TestAParameterIsReadAsTheKernelHoldsItWithItsSpacesMadeOne(t *testing.T) {
	kernel(t, map[string]string{
		"net/ipv4/ip_forward":                  "0\n",
		"net/ipv4/ip_local_port_range":         "32768\t60999\n",
		"net/ipv4/conf/eth0.100/rp_filter":     "1\n",
		"kernel/yama/ptrace_scope":             "  1  \n",
		"kernel/random/write_wakeup_threshold": "",
	})
	for name, want := range map[string]string{
		"net.ipv4.ip_forward":                  "0",
		"net.ipv4.ip_local_port_range":         "32768 60999",
		"net.ipv4.conf.eth0/100.rp_filter":     "1",
		"kernel.yama.ptrace_scope":             "1",
		"kernel.random.write_wakeup_threshold": "",
	} {
		if value, err := Read(name); err != nil || value != want {
			t.Errorf("%s reads as %q: %v, want %q", name, value, err, want)
		}
	}
	if _, err := Read("net.ipv6.conf.all.disable_ipv6"); !errors.Is(err, ErrAbsent) {
		t.Errorf("a parameter the kernel does not have was answered %v", err)
	}
}

func TestOnlyANameSysctlWritesIsReadAndNothingElseOfTheFilesystem(t *testing.T) {
	kernel(t, map[string]string{"net/ipv4/ip_forward": "0\n"})
	for _, name := range []string{"", ".", "net..ipv4", "net.ipv4.", ".net", "net/../../etc/shadow", "net.//.x", "net.ipv4/", "net ipv4", "kernel.*", string(make([]byte, 256))} {
		if _, err := Read(name); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q was answered %v", name, err)
		}
	}
	if path, err := Path("net.ipv4.conf.eth0/100.rp_filter"); err != nil || path != filepath.Join(root, "net", "ipv4", "conf", "eth0.100", "rp_filter") {
		t.Errorf("a name with a dot within a component reads %s: %v", path, err)
	}
}

func TestAParameterTheAccountMayNotReadIsDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser reads whatever the mode says")
	}
	kernel(t, map[string]string{"kernel/cad_pid": "1\n"})
	if err := os.Chmod(filepath.Join(root, "kernel", "cad_pid"), 0o200); err != nil {
		t.Fatal(err)
	}
	if _, err := Read("kernel.cad_pid"); !errors.Is(err, ErrDenied) {
		t.Fatalf("a parameter only the superuser reads was answered %v", err)
	}
}
