package machine

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// Whatever procfs says of the processors and the memory, the hardware read
// from it holds a memory in whole kibibytes and a speed a record carries, or is
// refused as unreadable.
func FuzzDescribed(f *testing.F) {
	f.Add([]byte("processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\ncpu MHz\t\t: 2445.426\n"), []byte("MemTotal:       16374092 kB\nMemFree:  1 kB\n"))
	f.Add([]byte("cpu MHz : 1e300\n"), []byte("MemTotal: 18446744073709551615 kB\n"))
	f.Add([]byte("model name : \xff\n"), []byte("MemTotal: x kB\n"))
	f.Fuzz(func(t *testing.T, cpuinfo, meminfo []byte) {
		kept, keptSys := proc, sys
		t.Cleanup(func() { proc, sys = kept, keptSys })
		proc, sys = t.TempDir(), t.TempDir()
		for name, content := range map[string][]byte{"cpuinfo": cpuinfo, "meminfo": meminfo} {
			if err := os.WriteFile(filepath.Join(proc, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		held, err := Described()
		switch {
		case err != nil && !errors.Is(err, ErrUnreadable):
			t.Fatalf("a refusal that names no reason: %v", err)
		case err == nil && (held.Memory%1024 != 0 || uint64(held.MHz) > math.MaxUint32):
			t.Fatalf("the hardware was read as %+v", held)
		}
	})
}

// Whatever procfs says the boot is, it is told only as a boot identifier, or
// refused as unreadable.
func FuzzBoot(f *testing.F) {
	for _, seed := range []string{"3f1c2b4a-5d6e-4f70-8192-a3b4c5d6e7f8\n", "", "3F1C2B4A-5D6E-4F70-8192-A3B4C5D6E7F8\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		kept := proc
		t.Cleanup(func() { proc = kept })
		proc = t.TempDir()
		if err := os.MkdirAll(filepath.Join(proc, "sys", "kernel", "random"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, "sys", "kernel", "random", "boot_id"), content, 0o644); err != nil {
			t.Fatal(err)
		}
		told, err := Boot()
		switch {
		case err != nil && !errors.Is(err, ErrUnreadable):
			t.Fatalf("a refusal that names no reason: %v", err)
		case err == nil && !bootPattern.MatchString(told):
			t.Fatalf("%q was told as boot %q", content, told)
		}
	})
}
