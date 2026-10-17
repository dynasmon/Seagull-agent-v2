package services

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Whatever systemctl lists, the services read from it are each named once, in
// order, none of them a template, and no unit file that is an alias of another
// is taken for a service of its own.
func FuzzMerge(f *testing.F) {
	f.Add([]byte(`[{"unit":"ssh.service","load":"loaded","active":"active","sub":"running","description":"OpenBSD Secure Shell server"},
		{"unit":"getty@tty1.service","load":"loaded","active":"active","sub":"running","description":"Getty on tty1"},
		{"unit":"gone.service","load":"not-found","active":"inactive","sub":"dead","description":"gone.service"}]`),
		[]byte(`[{"unit_file":"ssh.service","state":"enabled"},{"unit_file":"getty@.service","state":"enabled"},
		{"unit_file":"sshd.service","state":"alias"},{"unit_file":"rsync.service","state":"disabled"}]`))
	f.Add([]byte(`[{"unit":"ssh.service","load":"loaded","active":"active"},{"unit":"ssh.service","load":"loaded","active":"active"}]`), []byte(`[]`))
	f.Add([]byte(`[{"unit":"../x.service","load":"loaded","active":"active"}]`), []byte(`[{"unit_file":"x.service","state":""}]`))
	f.Fuzz(func(t *testing.T, listed, unitFiles []byte) {
		var units []loaded
		var files []unitFile
		if json.Unmarshal(listed, &units) != nil || json.Unmarshal(unitFiles, &files) != nil {
			return
		}
		held, err := merge(units, files)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(err.Error()) > 1<<10 {
				t.Fatalf("a listing was refused for no reason it names, or a long one: %.200v", err)
			}
			return
		}
		if !slices.IsSortedFunc(held, func(a, b Service) int { return strings.Compare(a.Name, b.Name) }) {
			t.Fatal("the services are not listed in order")
		}
		for index, service := range held {
			switch {
			case index > 0 && held[index-1].Name == service.Name:
				t.Fatalf("%s is listed twice", service.Name)
			case !named(service.Name) || strings.HasSuffix(service.Name, instanceOf) || service.Load == "" && service.File == aliased || service.Active == "":
				t.Fatalf("%+v was listed as a service", service)
			}
		}
	})
}

func FuzzUnit(f *testing.F) {
	for _, seed := range []string{"ssh.service", "getty@tty1.service", "-ssh.service", "--all", "dev-sda1.device", "a b.service", "x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if unit(name) && (strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t\n\x00=/") || len(name) > 255) {
			t.Fatalf("%q, which systemctl could read as something other than a unit, was asked for", name)
		}
	})
}
