package kmod

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func written(t *testing.T, root string, held map[string]string) {
	t.Helper()
	for name, content := range held {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func host(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	saved, savedSys, savedDirectories := modules, sysModule, directories
	modules, sysModule = filepath.Join(root, "proc", "modules"), filepath.Join(root, "sys", "module")
	directories = []string{filepath.Join(root, "etc"), filepath.Join(root, "run"), filepath.Join(root, "usr")}
	t.Cleanup(func() { modules, sysModule, directories = saved, savedSys, savedDirectories })
	return root
}

func TestAModuleIsLoadedBuiltInOrAbsentAsTheKernelShowsIt(t *testing.T) {
	root := host(t)
	written(t, root, map[string]string{
		"proc/modules":                     "tls 163840 0 - Live 0x0000000000000000\nusb_storage 86016 1 uas, Live 0x0000000000000000\n",
		"sys/module/vt/parameters/x":       "",
		"sys/module/udf/initstate":         "live\n",
		"sys/module/usb_storage/initstate": "live\n",
	})
	kernel, err := ReadKernel()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]State{"tls": Loaded, "usb-storage": Loaded, "vt": BuiltIn, "udf": Loaded, "cramfs": Absent} {
		if got, err := kernel.State(name); err != nil || got != want {
			t.Errorf("%s reads as %s: %v, want %s", name, got, err, want)
		}
	}
	if _, err := kernel.State("../../etc"); !errors.Is(err, ErrMalformed) {
		t.Errorf("a name that is no module was answered %v", err)
	}
}

func TestTheFirstInstallLineModprobeReadsIsTheOneItFollows(t *testing.T) {
	root := host(t)
	written(t, root, map[string]string{
		"usr/cramfs.conf":      "install cramfs /sbin/modprobe --ignore-install cramfs\n",
		"etc/cramfs.conf":      "# keep it out\ninstall cramfs /bin/false\nblacklist cramfs\n",
		"etc/10-squashfs.conf": "install squashfs \\\n  /bin/true\n",
		"run/20-squashfs.conf": "install squashfs /sbin/modprobe --ignore-install squashfs\n",
		"usr/usb.conf":         "install usb-storage /bin/true # not here\n",
		"etc/udf.alias":        "blacklist udf\n",
		"etc/.hidden.conf":     "install hfs /bin/false\n",
		"etc/notes.txt":        "install hfsplus /bin/false\n",
		"usr/globs.conf":       "install jffs* /bin/false\n",
	})
	held, err := ReadConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"cramfs":      "/bin/false",
		"squashfs":    "/bin/true",
		"usb_storage": "/bin/true # not here",
		"jffs2":       "/bin/false",
	} {
		rule, found := held.Install(name)
		if !found || rule.Command != want || !Refuses(rule.Command) {
			t.Errorf("%s installs as %+v, want %q", name, rule, want)
		}
	}
	if rule, _ := held.Install("cramfs"); rule.File != filepath.Join(root, "etc", "cramfs.conf") || rule.Line != 2 {
		t.Errorf("the install line for cramfs is read from %s line %d", rule.File, rule.Line)
	}
	if rule, _ := held.Install("squashfs"); rule.Line != 1 {
		t.Errorf("a line continued on the next is read at line %d", rule.Line)
	}
	for _, name := range []string{"hfs", "hfsplus", "udf"} {
		if rule, found := held.Install(name); found {
			t.Errorf("%s installs as %+v, which no file modprobe reads says", name, rule)
		}
	}
	if _, found := held.Blacklisted("cramfs"); !found {
		t.Error("cramfs is not read as blacklisted")
	}
	if _, found := held.Blacklisted("udf"); !found {
		t.Error("a blacklist line of an .alias file is not read")
	}
}

func TestOnlyACommandThatRunsNothingButFalseOrTrueKeepsAModuleOut(t *testing.T) {
	for command, refuses := range map[string]bool{
		"/bin/false":                             true,
		"/usr/bin/true":                          true,
		"/bin/true # disabled":                   true,
		"/bin/false; /sbin/modprobe cramfs":      false,
		"/sbin/modprobe --ignore-install cramfs": false,
		"true":                                   false,
		"/bin/echo cramfs":                       false,
		"":                                       false,
	} {
		if Refuses(command) != refuses {
			t.Errorf("%q keeps a module out: %t", command, !refuses)
		}
	}
}

func TestAConfigurationFileTheAgentCannotReadLeavesTheConfigurationUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser reads whatever the mode says")
	}
	root := host(t)
	written(t, root, map[string]string{"etc/private.conf": "install cramfs /bin/false\n"})
	if err := os.Chmod(filepath.Join(root, "etc", "private.conf"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfiguration(); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("a configuration file nobody may read was answered %v", err)
	}
}
