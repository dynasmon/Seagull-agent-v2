package spool_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

const (
	childSpool  = "SEAGULL_SPOOL_TEST_CHILD"
	crashBudget = 16 << 20
)

func TestMain(m *testing.M) {
	if arguments, ok := os.LookupEnv(childSpool); ok {
		os.Exit(child(arguments))
	}
	os.Exit(m.Run())
}

// A child admits records as fast as the spool takes them and acknowledges some
// of what it holds, and says so on its standard output only once the spool
// returned, so whatever it said before it was killed is what the spool promised.
// It also says which records it is about to acknowledge before it asks, since a
// kill can land once an acknowledgement is durable and before it is said.
func child(arguments string) int {
	directory, round, _ := strings.Cut(arguments, " ")
	root, err := os.OpenRoot(directory)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	held, err := spool.Open(root, spool.Limits{MaxBytes: crashBudget}, slog.New(slog.DiscardHandler))
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	for n := 0; ; n++ {
		records := make([]spool.Record, 1+n%5)
		ids := make([]string, len(records))
		for i := range records {
			ids[i] = fmt.Sprintf("r%s-%06d-%d", round, n, i)
			records[i] = spool.Record{ID: ids[i], Payload: crashPayload(ids[i])}
		}
		receipt, err := held.Admit(spool.Events, records...)
		if errors.Is(err, spool.ErrFull) {
			if !settle(held, 1<<20) {
				return 1
			}
			continue
		}
		if err != nil {
			fmt.Println("failed", err)
			return 1
		}
		fmt.Printf("admitted %d %s\n", receipt.First, strings.Join(ids, " "))
		if n%3 == 2 && !settle(held, 4) {
			return 1
		}
	}
}

func settle(held *spool.Spool, most int) bool {
	entries, err := held.Read(spool.Events, 1, most, 64<<20)
	if err != nil {
		fmt.Println("failed", err)
		return false
	}
	var sequences []string
	var settled []uint64
	for _, entry := range entries {
		settled = append(settled, entry.Sequence)
		sequences = append(sequences, strconv.FormatUint(entry.Sequence, 10))
	}
	fmt.Printf("acknowledging %s\n", strings.Join(sequences, " "))
	if err := held.Acknowledge(spool.Events, settled...); err != nil {
		fmt.Println("failed", err)
		return false
	}
	fmt.Printf("acknowledged %s\n", strings.Join(sequences, " "))
	return true
}

// Most records are small and one in sixteen spans several writes, so a kill
// lands between the writes of one record as often as between two records.
func crashPayload(id string) []byte {
	digest := sha256.Sum256([]byte(id))
	length := 1 + int(digest[0])*16
	if digest[1] < 16 {
		length = 150 << 10
	}
	return bytes.Repeat(digest[:], length/len(digest)+1)[:length]
}

func TestAKilledProcessKeepsEverythingItsSpoolAdmitted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot kill another process the way a crash does")
	}
	directory := spoolDirectory(t)
	admitted := map[uint64]string{}
	acknowledged, acknowledging := map[uint64]bool{}, map[uint64]bool{}
	for round := range 8 {
		kill(t, directory, round, 10+rand.IntN(120), admitted, acknowledged, acknowledging)

		held, logs := open(t, directory, crashBudget)
		if lost, found := logged(t, logs, "spool_records_lost"); found {
			t.Fatalf("round %d: killing the process lost records: %v", round, lost)
		}
		entries := drain(t, held, spool.Events)
		outstanding := map[uint64]bool{}
		for i, entry := range entries {
			if i > 0 && entry.Sequence <= entries[i-1].Sequence {
				t.Fatalf("round %d: record %d was read back after record %d", round, entry.Sequence, entries[i-1].Sequence)
			}
			if !bytes.Equal(entry.Payload, crashPayload(entry.ID)) {
				t.Fatalf("round %d: record %d, %s, was read back altered", round, entry.Sequence, entry.ID)
			}
			if id, said := admitted[entry.Sequence]; said && id != entry.ID {
				t.Fatalf("round %d: record %d was admitted as %s and read back as %s", round, entry.Sequence, id, entry.ID)
			}
			if acknowledged[entry.Sequence] {
				t.Fatalf("round %d: record %d is outstanding after its acknowledgement was confirmed", round, entry.Sequence)
			}
			outstanding[entry.Sequence] = true
		}
		for sequence, id := range admitted {
			if !acknowledged[sequence] && !acknowledging[sequence] && !outstanding[sequence] {
				t.Fatalf("round %d: record %d, %s, was admitted and is gone without an acknowledgement", round, sequence, id)
			}
		}
		closeSpool(t, held)
	}
	if len(admitted) == 0 || len(acknowledged) == 0 {
		t.Fatalf("the children admitted %d records and acknowledged %d", len(admitted), len(acknowledged))
	}
}

func kill(t *testing.T, directory string, round, after int, admitted map[uint64]string, acknowledged, acknowledging map[uint64]bool) {
	t.Helper()
	process := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	process.Env = append(os.Environ(), fmt.Sprintf("%s=%s %d", childSpool, directory, round))
	said, err := process.StdoutPipe()
	if err != nil {
		t.Fatalf("read what the child says: %v", err)
	}
	if err := process.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	lines := bufio.NewScanner(said)
	lines.Buffer(make([]byte, 64<<10), 1<<20)
	killed := false
	for count := 0; lines.Scan(); {
		fields := strings.Fields(lines.Text())
		switch {
		case len(fields) > 2 && fields[0] == "admitted":
			first, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("the child said %q", lines.Text())
			}
			for i, id := range fields[2:] {
				admitted[first+uint64(i)] = id
			}
			count++
		case len(fields) > 0 && (fields[0] == "acknowledged" || fields[0] == "acknowledging"):
			for _, field := range fields[1:] {
				sequence, err := strconv.ParseUint(field, 10, 64)
				if err != nil {
					t.Fatalf("the child said %q", lines.Text())
				}
				if fields[0] == "acknowledged" {
					acknowledged[sequence] = true
				} else {
					acknowledging[sequence] = true
				}
			}
		default:
			t.Fatalf("the child said %q", lines.Text())
		}
		if count >= after && !killed {
			if err := process.Process.Kill(); err != nil {
				t.Fatalf("kill the child: %v", err)
			}
			killed = true
		}
	}
	if err := process.Wait(); !killed || err == nil {
		t.Fatalf("round %d: the child ended with %v before it was killed", round, err)
	}
}
