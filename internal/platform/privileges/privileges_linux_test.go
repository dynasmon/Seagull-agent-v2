//go:build linux

package privileges

import (
	"slices"
	"strings"
	"testing"
)

func TestTheCapabilitiesTheProcessHoldsAreTheOnesItsStatusReports(t *testing.T) {
	cases := map[string]struct {
		status     string
		held       []string
		noNewPrivs bool
	}{
		"a process holding nothing": {
			status: "Uid:\t987\t987\t987\t987\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\n",
			// a bounding set it cannot use is not a capability it holds
			noNewPrivs: true,
		},
		"a process that may read any file": {
			status: "CapPrm:\t0000000000000004\nCapEff:\t0000000000000004\nCapBnd:\t000001ffffffffff\nNoNewPrivs:\t0\n",
			held:   []string{"CAP_DAC_READ_SEARCH"},
		},
		"a process holding what it does not use yet": {
			status: "CapPrm:\t0000000000002000\nCapEff:\t0000000000000000\nNoNewPrivs:\t0\n",
			held:   []string{"CAP_NET_RAW"},
		},
		"the superuser": {
			status: "CapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t0\n",
			held:   names(0x1ffffffffff),
		},
		"a capability this build does not name": {
			status: "CapPrm:\t8000000000000000\nCapEff:\t0000000000000000\nNoNewPrivs:\t0\n",
			held:   []string{"cap(63)"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			held, bounded, err := described(c.status)
			if err != nil {
				t.Fatalf("read the status of %s: %v", name, err)
			}
			if !slices.Equal(held, c.held) || bounded != c.noNewPrivs {
				t.Fatalf("%s holds %v with no_new_privs %t, want %v and %t", name, held, bounded, c.held, c.noNewPrivs)
			}
		})
	}
	if held := names(0x1ffffffffff); len(held) != len(named) || !slices.Contains(held, "CAP_CHECKPOINT_RESTORE") {
		t.Fatalf("the superuser holds %d capabilities, this build names %d", len(held), len(named))
	}
}

func TestAStatusThatDoesNotSayWhatTheProcessMayDoIsRefused(t *testing.T) {
	cases := map[string]string{
		"a status with no capability at all": "Uid:\t987\t987\t987\t987\n",
		"a status missing what it may use":   "CapPrm:\t0000000000000000\nNoNewPrivs:\t0\n",
		"a status missing its bound":         "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n",
		"a capability set that is not one":   "CapPrm:\tnone\nCapEff:\t0000000000000000\nNoNewPrivs:\t0\n",
		"a capability set beyond 64 bits":    "CapPrm:\tffffffffffffffffff\nCapEff:\t0\nNoNewPrivs:\t0\n",
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			held, bounded, err := described(status)
			if err == nil {
				t.Fatalf("%s described a process holding %v with no_new_privs %t", name, held, bounded)
			}
			if !strings.Contains(err.Error(), "Cap") && !strings.Contains(err.Error(), "NoNewPrivs") {
				t.Errorf("%s was refused with %v", name, err)
			}
		})
	}
}
