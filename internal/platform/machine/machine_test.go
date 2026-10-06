package machine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const ubuntu = `PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.5 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
`

func place(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func releasedAt(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	held := releases
	releases = []string{filepath.Join(directory, "etc/os-release"), filepath.Join(directory, "usr/lib/os-release")}
	t.Cleanup(func() { releases = held })
	return releases[0], releases[1]
}

func TestTheDistributionIsWhatOsReleaseSays(t *testing.T) {
	etc, usr := releasedAt(t)
	place(t, usr, ubuntu)
	held, err := Distribution()
	if err != nil {
		t.Fatal(err)
	}
	want := Release{ID: "ubuntu", Like: []string{"debian"}, Name: "Ubuntu", Version: "24.04", Codename: "noble"}
	if held.ID != want.ID || !slices.Equal(held.Like, want.Like) || held.Name != want.Name || held.Version != want.Version || held.Codename != want.Codename || held.Build != "" {
		t.Errorf("the distribution is %+v, want %+v", held, want)
	}

	place(t, etc, "# a comment\n\nNAME='Rocky Linux'\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\nBUILD_ID=\"a \\\"quoted\\\" \\$build\\\\\"\n")
	held, err = Distribution()
	if err != nil {
		t.Fatal(err)
	}
	if held.Name != "Rocky Linux" || held.ID != "rocky" || !slices.Equal(held.Like, []string{"rhel", "centos", "fedora"}) || held.Version != "9.4" || held.Build != `a "quoted" $build\` {
		t.Errorf("/etc/os-release, which comes first, was read as %+v", held)
	}

	place(t, etc, "VERSION_ID=1\n")
	if held, err := Distribution(); err != nil || held.ID != "linux" || held.Name != "Linux" {
		t.Errorf("an os-release that names no distribution was read as %+v and %v, and os-release(5) says Linux", held, err)
	}
}

func TestAnOsReleaseThatDoesNotReadIsRefusedWhole(t *testing.T) {
	etc, _ := releasedAt(t)
	if _, err := Distribution(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a host with no os-release was read as %v", err)
	}
	for name, content := range map[string]string{
		"a line with no value":      "ID=ubuntu\nNAME\n",
		"a lowercase key":           "id=ubuntu\n",
		"an unquoted space":         "NAME=Ubuntu Linux\n",
		"a quote left open":         "NAME=\"Ubuntu\n",
		"a substitution":            "NAME=\"$(id)\"\n",
		"a single quote inside":     "NAME='it's'\n",
		"an unescaped double quote": "NAME=\"a \" b\"\n",
		"a command substitution":    "NAME=`id`\n",
	} {
		place(t, etc, content)
		if held, err := Distribution(); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: os-release was read as %+v and %v", name, held, err)
		}
	}
}

func hardwareAt(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	heldProc, heldSys := proc, sys
	proc, sys = filepath.Join(directory, "proc"), filepath.Join(directory, "sys")
	t.Cleanup(func() { proc, sys = heldProc, heldSys })
	return proc, sys
}

func TestTheHardwareIsWhatProcfsAndSysfsShow(t *testing.T) {
	proc, sys := hardwareAt(t)
	place(t, filepath.Join(proc, "cpuinfo"), "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD Ryzen 7 5700X 8-Core Processor\ncpu MHz\t\t: 3393.661\n\nprocessor\t: 1\nmodel name\t: another\ncpu MHz\t\t: 1200.000\n")
	place(t, filepath.Join(proc, "meminfo"), "MemTotal:       16323988 kB\nMemFree:          123456 kB\n")
	for cpu, shared := range map[string]string{"cpu0": "0-1", "cpu1": "0-1", "cpu2": "2-3", "cpu3": "2-3", "cpu4": "4"} {
		place(t, filepath.Join(sys, "devices/system/cpu", cpu, "topology/core_cpus_list"), shared+"\n")
	}
	place(t, filepath.Join(sys, "devices/system/cpu/cpu5/topology/thread_siblings_list"), "5\n")
	place(t, filepath.Join(sys, "devices/system/cpu/cpufreq/policy0/scaling_max_freq"), "1\n")
	place(t, filepath.Join(sys, "class/dmi/id/sys_vendor"), "VMware, Inc.\n")
	place(t, filepath.Join(sys, "class/dmi/id/product_name"), "VMware Virtual Platform\n")
	held, err := Described()
	if err != nil {
		t.Fatal(err)
	}
	want := Hardware{CPU: "AMD Ryzen 7 5700X 8-Core Processor", Cores: 4, MHz: 3394, Memory: 16323988 * 1024, Vendor: "VMware, Inc.", Model: "VMware Virtual Platform"}
	if held != want {
		t.Errorf("the hardware is %+v, want %+v", held, want)
	}

	place(t, filepath.Join(sys, "devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"), "4661000\n")
	if held, err := Described(); err != nil || held.MHz != 4661 {
		t.Errorf("with a frequency the processor reaches at most, the hardware is %+v and %v", held, err)
	}
}

func TestHardwareTheHostDoesNotDescribeIsLeftEmpty(t *testing.T) {
	proc, _ := hardwareAt(t)
	if _, err := Described(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a host with no /proc/cpuinfo was described as %v", err)
	}
	place(t, filepath.Join(proc, "cpuinfo"), "processor\t: 0\nBogoMIPS\t: 48.00\nCPU implementer\t: 0x41\n")
	if _, err := Described(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a host with no /proc/meminfo was described as %v", err)
	}
	place(t, filepath.Join(proc, "meminfo"), "MemTotal:       a lot\n")
	if _, err := Described(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a memory that is no number was described as %v", err)
	}
	place(t, filepath.Join(proc, "meminfo"), "MemTotal:       1024 kB\n")
	held, err := Described()
	if err != nil || held != (Hardware{Memory: 1 << 20}) {
		t.Errorf("an arm host with no firmware tables was described as %+v and %v", held, err)
	}
}

func TestThisHostIsDescribed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent describes linux hosts")
	}
	release, err := Distribution()
	if err != nil || release.ID == "" || release.Name == "" {
		t.Errorf("this host runs %+v, %v", release, err)
	}
	kernel, err := Running()
	booted, read := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil || read != nil || kernel.Name != "Linux" || kernel.Release != strings.TrimSpace(string(booted)) || kernel.Version == "" || kernel.Machine == "" {
		t.Errorf("this host booted %+v, %v", kernel, err)
	}
	hardware, err := Described()
	if err != nil || hardware.Memory == 0 {
		t.Errorf("this host is made of %+v, %v", hardware, err)
	}
}
