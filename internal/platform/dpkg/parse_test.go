package dpkg

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Whatever dpkg-query writes, the list read from it is the packages dpkg keeps
// files of, each as dpkg-query would write it again, or it is refused whole.
func FuzzParse(f *testing.F) {
	f.Add([]byte("openssh-server\t1:9.6p1-3ubuntu13.5\tamd64\topenssh\t1:9.6p1-3ubuntu13.5\t1951\tinstalled\n" +
		"libc6\t2.39-0ubuntu8.4\tamd64\tglibc\t2.39-0ubuntu8.4\t\thalf-configured\n" +
		"old-tool\t1.0\tall\told-tool\t1.0\t12\tconfig-files\n"))
	f.Add([]byte("bash\t5.2.21-2ubuntu4\tamd64\tbash\t5.2.21-2ubuntu4\t1830\tinstalled"))
	f.Add([]byte("bash\t5.2\tamd64\tbash\t5.2\t-1\tinstalled\n"))
	f.Add([]byte("bash\t5.2\tamd64\tbash\t5.2\t1\tremoved\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, written []byte) {
		held, err := parse(written)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(err.Error()) > 1<<10 {
				t.Fatalf("a list was refused for no reason it names, or a long one: %.200v", err)
			}
			return
		}
		var again strings.Builder
		for _, installed := range held {
			if present, known := unpacked[installed.Status]; !present || !known || installed.Name == "" {
				t.Fatalf("package %q in state %q was read as on the host", installed.Name, installed.Status)
			}
			size := strconv.FormatUint(installed.InstalledKiB, 10)
			again.WriteString(strings.Join([]string{installed.Name, installed.Version, installed.Architecture, installed.Source, installed.SourceVersion, size, installed.Status}, "\t") + "\n")
		}
		reread, err := parse([]byte(again.String()))
		if err != nil || !slices.Equal(reread, held) {
			t.Fatalf("the packages read were written again as a list that reads as %d of %d: %v", len(reread), len(held), err)
		}
	})
}
