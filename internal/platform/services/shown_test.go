package services

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Whatever systemctl show writes of the units asked for, each is read as the
// unit it says, in the order asked, as what writing it again reads as.
func FuzzShow(f *testing.F) {
	f.Add([]byte("Id=ssh.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\nId=gone.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n"))
	f.Add([]byte("Id=ssh.service\nLoadState=loaded\nActiveState=active\n\n\n\nId=x\n"))
	f.Add([]byte("Id=a=b\nLoadState= loaded \nActiveState=active\nUnitFileState=enabled \n\nId=b\nLoadState=masked\nActiveState=inactive\n"))
	asked := []string{"ssh.service", "sshd.service"}
	f.Fuzz(func(t *testing.T, written []byte) {
		held, err := shownOf(written, asked)
		if err != nil {
			return
		}
		var again strings.Builder
		for index, unit := range held {
			if unit.Asked != asked[index] || unit.ID == "" || unit.Load == "" || unit.Active == "" {
				t.Fatalf("unit %d was read as %+v", index, unit)
			}
			fmt.Fprintf(&again, "Id=%s\nLoadState=%s\nActiveState=%s\nUnitFileState=%s\n\n", unit.ID, unit.Load, unit.Active, unit.File)
		}
		reread, err := shownOf([]byte(again.String()), asked)
		if err != nil || !slices.Equal(reread, held) {
			t.Fatalf("the units read were written again as %q, which reads as %+v: %v", again.String(), reread, err)
		}
	})
}
