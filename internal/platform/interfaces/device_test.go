package interfaces

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Whatever sysfs says of an interface, it is read as the interface its
// attributes describe, up only when its flags and its state both say so, or it
// is refused as unreadable.
func FuzzDevice(f *testing.F) {
	f.Add("2", "00:0c:29:7d:4b:3c", "1500", "1", "0x1003", "up", "INTERFACE=ens33\nIFINDEX=2\n")
	f.Add("1", "00:00:00:00:00:00", "65536", "772", "0x9", "unknown", "")
	f.Add("x", "", "-1", "1", "zz", "down", "DEVTYPE=bridge\n")
	f.Fuzz(func(t *testing.T, index, address, mtu, link, flags, operstate, uevent string) {
		kept := classes
		t.Cleanup(func() { classes = kept })
		classes = t.TempDir()
		described := filepath.Join(classes, "ens33")
		if err := os.Mkdir(described, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{"ifindex": index, "address": address, "mtu": mtu, "type": link, "flags": flags, "operstate": operstate, "uevent": uevent} {
			if err := os.WriteFile(filepath.Join(described, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		held, found, err := device("ens33")
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(err.Error()) > 1<<10 {
				t.Fatalf("a refusal that names no reason, or a long one: %.200v", err)
			}
			return
		}
		raised, _ := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(flags), "0x"), 16, 32)
		state := strings.TrimSpace(operstate)
		if !found || held.Name != "ens33" || held.Up != (raised&up != 0 && (state == "up" || state == "unknown")) {
			t.Fatalf("an interface flagged %q and %q was read as %+v", flags, operstate, held)
		}
	})
}
