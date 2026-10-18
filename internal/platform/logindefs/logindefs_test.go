package logindefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func defined(t *testing.T, content string) {
	t.Helper()
	held := filepath.Join(t.TempDir(), "login.defs")
	if err := os.WriteFile(held, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := path
	path = held
	t.Cleanup(func() { path = saved })
}

func TestTheLastLineNamingAnItemIsTheOneTheShadowUtilitiesApply(t *testing.T) {
	defined(t, "# login.defs\n"+
		"PASS_MAX_DAYS\t99999\n"+
		"UMASK  022\n"+
		"  ENV_PATH  PATH=/usr/local/bin:/usr/bin  \n"+
		"ENCRYPT_METHOD \"SHA512\"\n"+
		"PASS_MAX_DAYS 365\n"+
		"UMASK\v\n"+
		"MAIL_DIR\n")
	held, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"PASS_MAX_DAYS":  "365",
		"UMASK":          "022",
		"ENV_PATH":       "PATH=/usr/local/bin:/usr/bin",
		"ENCRYPT_METHOD": "SHA512",
	} {
		if got, found := held[name]; !found || got.Value != want {
			t.Errorf("%s reads as %+v, want %q", name, got, want)
		}
	}
	if held["PASS_MAX_DAYS"].Line != 6 {
		t.Errorf("PASS_MAX_DAYS is read from line %d, and the last line setting it is 6", held["PASS_MAX_DAYS"].Line)
	}
	if setting, found := held["MAIL_DIR"]; found {
		t.Errorf("MAIL_DIR, named without a value, reads as %+v, and the shadow utilities set nothing from such a line", setting)
	}
	if _, found := held["pass_max_days"]; found {
		t.Error("an item is named without regard to case, and the shadow utilities name it with regard to it")
	}
}

func TestAHostWithoutLoginDefsHasNone(t *testing.T) {
	saved := path
	path = filepath.Join(t.TempDir(), "login.defs")
	t.Cleanup(func() { path = saved })
	if _, err := Read(); !errors.Is(err, ErrAbsent) {
		t.Fatalf("a host without login.defs was answered %v", err)
	}
}
