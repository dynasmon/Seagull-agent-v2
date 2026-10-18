package processes

import (
	"strconv"
	"strings"
	"testing"
)

// Whatever the status of a process says, the account it acts as is the
// effective one its first Uid line names, or none.
func FuzzActing(f *testing.F) {
	f.Add([]byte("Name:\tsshd\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"))
	f.Add([]byte("Uid:\t1000\t997\t997\t997\nUid:\t0\t0\t0\t0\n"))
	f.Add([]byte("Uid:\t1\t2\t3\nUid:\t4\t5\t6\t7\n"))
	f.Fuzz(func(t *testing.T, status []byte) {
		user, err := acting(status)
		if err != nil {
			return
		}
		for line := range strings.SplitSeq(string(status), "\n") {
			if written, found := strings.CutPrefix(line, "Uid:"); found {
				ids := strings.Fields(written)
				if len(ids) != 4 {
					t.Fatalf("a process whose status says %q acts as %d", line, user)
				}
				if effective, err := strconv.ParseUint(ids[1], 10, 32); err != nil || uint32(effective) != user {
					t.Fatalf("a process whose status says %q acts as %d", line, user)
				}
				return
			}
		}
		t.Fatalf("a process whose status names no account acts as %d", user)
	})
}
