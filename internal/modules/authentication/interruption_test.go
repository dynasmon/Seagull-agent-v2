package authentication_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/authentication"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

const childCollector = "SEAGULL_AUTHENTICATION_TEST_CHILD"

func TestMain(m *testing.M) {
	if arguments, ok := os.LookupEnv(childCollector); ok {
		os.Exit(child(arguments))
	}
	os.Exit(m.Run())
}

type instructions struct {
	Base    string          `json:"base"`
	Entries []journal.Entry `json:"entries"`
	Hold    string          `json:"hold"`
}

// A child collects as the agent does and says on its standard output what it
// is about to do with the spool before it does it, and that it did. Told to
// hold at one of those points, it stops there until it is killed.
func child(arguments string) int {
	var told instructions
	if err := json.Unmarshal([]byte(arguments), &told); err != nil {
		fmt.Println("failed", err)
		return 1
	}
	logger := slog.New(slog.DiscardHandler)
	root, err := os.OpenRoot(filepath.Join(told.Base, "spool"))
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	kept, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, logger)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	directory, err := os.OpenRoot(filepath.Join(told.Base, "collection"))
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	collector, err := authentication.New(authentication.Options{
		Installation: installation,
		Spool:        &announcing{spool: kept, hold: told.Hold},
		Governor:     governed,
		Directory:    directory,
		Logger:       logger,
		Open:         newJournal(told.Entries...).Open,
	})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	fmt.Println("collecting")
	if err := collector.Collect(context.Background()); err != nil {
		fmt.Println("failed", err)
		return 1
	}
	return 0
}

type announcing struct {
	spool      *spool.Spool
	hold       string
	admissions int
}

func (a *announcing) Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error) {
	a.admissions++
	a.say(fmt.Sprintf("admitting %d", a.admissions))
	receipt, err := a.spool.Admit(stream, records...)
	if err != nil {
		fmt.Println("failed", err)
	}
	a.say(fmt.Sprintf("admitted %d", a.admissions))
	return receipt, err
}

func (a *announcing) Room(stream spool.Stream) int64 { return a.spool.Room(stream) }

func (a *announcing) say(point string) {
	fmt.Println(point)
	if point == a.hold {
		time.Sleep(time.Hour)
	}
}

// Killed at each point the card names, before the events reach the spool,
// after the spool made them durable and before the place in the journal moves
// past them, and once it did, the collector started again on what it left
// behind admits every event the journal holds: none is lost, and the events
// it admitted twice are the same events, byte for byte.
func TestAKilledCollectorLosesNothingAndAdmitsTheSameEventsAgain(t *testing.T) {
	now := time.Now().UTC()
	var entries []journal.Entry
	for i := 1; i <= 300; i++ {
		entries = append(entries, failed(i, now))
	}
	for _, point := range []struct {
		hold    string
		place   string
		spooled int
		twice   int
	}{
		{hold: "admitting 1", place: "", spooled: 0, twice: 0},
		{hold: "admitted 1", place: "", spooled: 256, twice: 256},
		{hold: "admitting 2", place: cursor(256), spooled: 256, twice: 0},
		{hold: "admitted 2", place: cursor(256), spooled: 300, twice: 44},
	} {
		t.Run(point.hold, func(t *testing.T) {
			base := t.TempDir()
			for _, name := range []string{"spool", "collection"} {
				if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			placed := `{"format":1,"since":"` + now.Add(-time.Hour).Format(time.RFC3339Nano) + `"}`
			if err := os.WriteFile(filepath.Join(base, "collection", authentication.Name+".json"), []byte(placed), 0o600); err != nil {
				t.Fatal(err)
			}
			kill(t, instructions{Base: base, Entries: entries, Hold: point.hold})

			h := reopen(t, base, newJournal(entries...))
			if place := h.place(); fmt.Sprint(place["cursor"]) != point.place && !(point.place == "" && place["cursor"] == nil) {
				t.Fatalf("killed at %s the collector had written down %v", point.hold, place)
			}
			if spooled := len(h.admitted()); spooled != point.spooled {
				t.Fatalf("killed at %s the spool held %d events, want %d", point.hold, spooled, point.spooled)
			}
			collecting := h.run(h.collector(nil))
			held := h.await(300 + point.twice)
			collecting.stop(t)
			seen := map[string][]byte{}
			ports := map[int]bool{}
			for _, entry := range held {
				if first, again := seen[entry.ID]; again && !bytes.Equal(first, entry.Payload) {
					t.Errorf("event %s was admitted twice with different bytes", entry.ID)
				}
				seen[entry.ID] = entry.Payload
				ports[port(t, entry)] = true
			}
			if len(held) != 300+point.twice || len(seen) != 300 || len(ports) != 300 {
				t.Errorf("after a kill at %s the spool holds %d events, %d distinct, from %d entries", point.hold, len(held), len(seen), len(ports))
			}
			if place := h.place(); place["cursor"] != cursor(300) {
				t.Errorf("after the restart the collector wrote down %v", place)
			}
		})
	}
}

func kill(t *testing.T, told instructions) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arguments, err := json.Marshal(told)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(self, "-test.run=^$")
	command.Env = append(os.Environ(), childCollector+"="+string(arguments))
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	said := bufio.NewScanner(output)
	var heard []string
	held := false
	for said.Scan() {
		heard = append(heard, said.Text())
		if said.Text() == told.Hold {
			held = true
			break
		}
		if strings.HasPrefix(said.Text(), "failed") {
			break
		}
	}
	command.Process.Kill()
	command.Wait()
	if !held {
		t.Fatalf("the child never reached %s, and said %q", told.Hold, heard)
	}
}

func reopen(t *testing.T, base string, held *fakeJournal) *harness {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join(base, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	log := &logged{}
	logger := slog.New(slog.NewJSONHandler(log, nil))
	kept, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kept.Close() })
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, directory: filepath.Join(base, "collection"), spool: kept, governor: governed, journal: held, log: log}
}
