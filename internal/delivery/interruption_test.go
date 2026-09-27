package delivery_test

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/delivery"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

const childDelivery = "SEAGULL_DELIVERY_TEST_CHILD"

func TestMain(m *testing.M) {
	if arguments, ok := os.LookupEnv(childDelivery); ok {
		os.Exit(child(arguments))
	}
	os.Exit(m.Run())
}

type instructions struct {
	Spool     string   `json:"spool"`
	Keys      string   `json:"keys"`
	KeyID     string   `json:"key_id"`
	Chain     [][]byte `json:"chain"`
	Authority []byte   `json:"authority"`
	URL       string   `json:"url"`
	Hold      string   `json:"hold"`
	Batch     int      `json:"batch"`
	Rate      int64    `json:"rate"`
}

// A child delivers what its spool holds as the agent does, and says on its
// standard output what it is about to do before it does it: send a batch,
// write down an acknowledgement, and that it wrote one down. Told to hold at
// one of those points, it stops there until it is killed.
func child(arguments string) int {
	var told instructions
	if err := json.Unmarshal([]byte(arguments), &told); err != nil {
		fmt.Println("failed", err)
		return 1
	}
	root, err := os.OpenRoot(told.Spool)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	held, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, slog.New(slog.DiscardHandler))
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	keys, err := os.OpenRoot(told.Keys)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	provider, err := pki.OpenKeyFiles(keys)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	authority, err := x509.ParseCertificate(told.Authority)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	client, err := transport.New(transport.Options{
		Authorities:      []*x509.Certificate{authority},
		Credentials:      &credential{keyID: told.KeyID, chain: told.Chain, provider: provider},
		ConnectTimeout:   time.Second,
		RequestTimeout:   30 * time.Second,
		MaxResponseBytes: 64 << 10,
		MaxConnections:   2,
	})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	logger := slog.New(slog.DiscardHandler)
	governed, err := governor.New(logger, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11",
		governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 2, UploadBytesPerSecond: told.Rate})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	delivered, err := delivery.New(delivery.Options{
		Spool:    settling{Spool: held, hold: told.Hold},
		Client:   announcing{Client: client, hold: told.Hold == "sending"},
		Governor: governed,
		URL:      told.URL,
		Batching: func() delivery.Batching {
			return delivery.Batching{MaxBytes: 4 << 20, MaxEvents: told.Batch, MaxInventoryRecords: told.Batch}
		},
		Policy: fast,
		Logger: logger,
	})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	fmt.Println("failed", delivered.Run(context.Background()))
	return 1
}

type announcing struct {
	delivery.Client
	hold bool
}

func (a announcing) Post(ctx context.Context, request transport.Request) (transport.Reply, error) {
	fmt.Println("sending")
	if a.hold {
		time.Sleep(time.Hour)
	}
	return a.Client.Post(ctx, request)
}

type settling struct {
	*spool.Spool
	hold string
}

func (s settling) Acknowledge(stream spool.Stream, sequences ...uint64) error {
	said := fmt.Sprint(sequences)
	fmt.Println("acknowledging", strings.Trim(said, "[]"))
	if s.hold == "acknowledging" {
		time.Sleep(time.Hour)
	}
	err := s.Spool.Acknowledge(stream, sequences...)
	if err == nil {
		fmt.Println("acknowledged", strings.Trim(said, "[]"))
	}
	if s.hold == "acknowledged" {
		time.Sleep(time.Hour)
	}
	return err
}

type childProcess struct {
	process *exec.Cmd
	lines   chan string
}

func start(t *testing.T, directory string, serving *platform, holding *credential, told instructions) *childProcess {
	t.Helper()
	told.Spool, told.Keys, told.KeyID, told.Chain = directory, holding.keys, holding.keyID, holding.chain
	told.Authority, told.URL = serving.trusted[0].Raw, serving.URL
	if told.Batch == 0 {
		told.Batch = 1000
	}
	if told.Rate == 0 {
		told.Rate = 1 << 30
	}
	encoded, err := json.Marshal(told)
	if err != nil {
		t.Fatalf("encode what the child is told: %v", err)
	}
	process := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	process.Env = append(os.Environ(), childDelivery+"="+string(encoded))
	said, err := process.StdoutPipe()
	if err != nil {
		t.Fatalf("read what the child says: %v", err)
	}
	if err := process.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	running := &childProcess{process: process, lines: make(chan string, 1024)}
	go func() {
		defer close(running.lines)
		lines := bufio.NewScanner(said)
		for lines.Scan() {
			running.lines <- lines.Text()
		}
	}()
	return running
}

func (c *childProcess) await(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.After(settle)
	for {
		select {
		case line, open := <-c.lines:
			if !open {
				t.Fatalf("the child ended before it said %q", prefix)
			}
			if strings.HasPrefix(line, "failed") {
				t.Fatalf("the child said %q", line)
			}
			if strings.HasPrefix(line, prefix) {
				return line
			}
		case <-deadline:
			t.Fatalf("the child did not say %q within %s", prefix, settle)
		}
	}
}

func (c *childProcess) within(t *testing.T, prefix string, wait time.Duration) bool {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case line, open := <-c.lines:
			if !open || strings.HasPrefix(line, "failed") {
				t.Fatalf("the child ended or failed: %q", line)
			}
			if strings.HasPrefix(line, prefix) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func (c *childProcess) kill(t *testing.T) {
	t.Helper()
	if err := c.process.Process.Kill(); err != nil {
		t.Fatalf("kill the child: %v", err)
	}
	if err := c.process.Wait(); err == nil {
		t.Fatal("the child ended on its own")
	}
	for range c.lines {
	}
}

func segments(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	kept := map[string][]byte{}
	found, err := filepath.Glob(filepath.Join(directory, "*", "*.seg"))
	if err != nil {
		t.Fatalf("list the segments of %s: %v", directory, err)
	}
	for _, path := range found {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		kept[path] = content
	}
	return kept
}

// Each case kills the process delivering a batch at one of the points a crash
// can fall between reading records and reclaiming them, then delivers again
// from what the spool kept. However the first process ended, every record
// reaches the platform's store once, as the bytes it was admitted as, and
// the only records the platform receives again are those it may already hold
// without the agent having written that down.
func TestADeliveryKilledAtAnyPointLosesNothingAndRepeatsOnlyWhatItCouldNotKnow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot kill another process the way a crash does")
	}
	cases := map[string]struct {
		hold      string
		rate      int64
		interrupt func(serving *platform, killing chan<- struct{})
		kept      int
		published int
		repeated  bool
	}{
		"before a batch is sent": {hold: "sending", kept: 6, published: 0},
		"while a batch is on its way": {
			rate: 64 << 10, kept: 6, published: 0,
			interrupt: func(serving *platform, killing chan<- struct{}) {
				serving.interceptWith(func(w http.ResponseWriter, r *http.Request) bool {
					io.ReadFull(r.Body, make([]byte, 512))
					close(killing)
					io.Copy(io.Discard, r.Body)
					return true
				})
			},
		},
		"after the platform published a batch and before it answered": {
			kept: 6, published: 6, repeated: true,
			interrupt: func(serving *platform, killing chan<- struct{}) {
				serving.set(func(w http.ResponseWriter, arrived *received) bool {
					serving.publish(arrived, len(arrived.ids))
					close(killing)
					<-arrived.gone
					return true
				})
			},
		},
		"after the answer and before the acknowledgement is written down":             {hold: "acknowledging", kept: 6, published: 6, repeated: true},
		"after the acknowledgement is written down and before the segment is removed": {hold: "acknowledged", kept: 0, published: 6},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			serving := emulate(t)
			holding := enrolled(t, serving)
			directory := spoolDirectory(t)
			held := spoolIn(t, directory)
			ids := admitEvents(t, held, "event", 5)
			large := event("event-large", time.Now())
			large.GetAuthentication().RawRecord = strings.Repeat("sshd[812]: Failed password for root ", 4<<10)
			if _, err := held.Admit(spool.Events, spool.Record{ID: "event-large", Payload: marshal(t, large)}); err != nil {
				t.Fatalf("admit: %v", err)
			}
			ids = append(ids, "event-large")
			slices.Sort(ids)
			if err := held.Close(); err != nil {
				t.Fatalf("close the spool: %v", err)
			}
			before := segments(t, directory)

			killing := make(chan struct{})
			if c.interrupt != nil {
				c.interrupt(serving, killing)
			}
			delivering := start(t, directory, serving, holding, instructions{Hold: c.hold, Rate: c.rate})
			switch c.hold {
			case "":
				select {
				case <-killing:
				case <-time.After(settle):
					t.Fatal("the platform never reached the point the child is killed at")
				}
			default:
				delivering.await(t, map[string]string{"sending": "sending", "acknowledging": "acknowledging", "acknowledged": "acknowledged"}[c.hold])
			}
			delivering.kill(t)
			first := serving.received()
			if published := len(serving.storedIDs(protocol.Events)); published != c.published {
				t.Fatalf("before the kill the platform published %d records, want %d", published, c.published)
			}
			if c.hold == "acknowledged" {
				for path, content := range before {
					if _, err := os.Lstat(path); err != nil {
						if err := os.WriteFile(path, content, 0o600); err != nil {
							t.Fatalf("restore %s: %v", path, err)
						}
					}
				}
			}

			serving.set(nil)
			serving.interceptWith(nil)
			reopened := spoolIn(t, directory)
			if kept := outstanding(reopened, spool.Events); kept.Outstanding != uint64(c.kept) || kept.Lost != 0 {
				t.Fatalf("after the kill the spool counts %+v, want %d outstanding", kept, c.kept)
			}
			deliver(t, reopened, serving, holding, nil)
			eventually(t, "delivering what the spool kept", func() bool { return outstanding(reopened, spool.Events).Outstanding == 0 })
			if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, ids) || len(serving.conflicting()) != 0 {
				t.Fatalf("the platform stores %v, conflicts %v", stored, serving.conflicting())
			}
			if kept := outstanding(reopened, spool.Events); kept.Delivered != 6 || kept.Lost+kept.Quarantined+kept.Expired != 0 {
				t.Fatalf("the spool counts %+v", kept)
			}
			for _, id := range ids {
				want := 1
				if c.repeated {
					want = 2
				}
				if published := serving.publications(protocol.Events, id); published != want {
					t.Errorf("%s was published %d times, want %d", id, published, want)
				}
			}
			later := serving.received()[len(first):]
			if c.kept == 0 && len(later) != 0 {
				t.Fatalf("records whose acknowledgement was written down were sent again in %d batches", len(later))
			}
			for _, again := range later {
				for _, earlier := range first {
					if again.id == earlier.id {
						t.Fatalf("batch %s was sent again under its identifier after a restart rebuilt it", again.id)
					}
				}
			}
		})
	}
}

// Children deliver the same spool one after another, each killed at a moment
// drawn at random, while the platform answers some batches with a failure
// after publishing part of them, loses the answers to others and miscounts
// others still. After every kill, every record the spool no longer holds is
// in the platform's store, and every record admitted is in one or the other.
func TestKillingTheDeliveryOverAndOverNeverSettlesARecordThePlatformDoesNotHold(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot kill another process the way a crash does")
	}
	serving := emulate(t)
	holding := enrolled(t, serving)
	directory := spoolDirectory(t)
	seed := uint64(time.Now().UnixNano())
	t.Logf("drawing with seed %d", seed)
	var drawing sync.Mutex
	drawn := rand.New(rand.NewPCG(seed, 7))
	draw := func(n int) int {
		drawing.Lock()
		defer drawing.Unlock()
		return drawn.IntN(n)
	}
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		switch chance := draw(10); {
		case chance == 0:
			serving.publish(arrived, draw(len(arrived.ids)+1))
			refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
		case chance == 1:
			serving.publish(arrived, len(arrived.ids))
			if hijacked, _, err := w.(http.Hijacker).Hijack(); err == nil {
				hijacked.Close()
			}
		case chance == 2:
			serving.publish(arrived, len(arrived.ids))
			acknowledge(w, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(arrived.ids) + 1)})
		default:
			return false
		}
		return true
	})
	admitted := map[uint64]string{}
	for round := range 8 {
		held := spoolIn(t, directory)
		for sequence := range outstandingIDs(t, held) {
			if _, known := admitted[sequence]; !known {
				t.Fatalf("round %d: record %d is outstanding and was never admitted", round, sequence)
			}
		}
		records := make([]spool.Record, 20+draw(60))
		for i := range records {
			id := fmt.Sprintf("round%d-%04d", round, i)
			records[i] = spool.Record{ID: id, Payload: marshal(t, event(id, time.Now()))}
		}
		receipt, err := held.Admit(spool.Events, records...)
		if err != nil {
			t.Fatalf("round %d: admit: %v", round, err)
		}
		for i, record := range records {
			admitted[receipt.First+uint64(i)] = record.ID
		}
		if err := held.Close(); err != nil {
			t.Fatalf("round %d: close the spool: %v", round, err)
		}

		delivering := start(t, directory, serving, holding, instructions{Batch: 3 + draw(8)})
		for range 1 + draw(12) {
			if !delivering.within(t, "acknowledged", time.Second) {
				break
			}
		}
		if draw(2) == 0 {
			time.Sleep(time.Duration(draw(20)) * time.Millisecond)
		}
		delivering.kill(t)

		reopened := spoolIn(t, directory)
		left := outstandingIDs(t, reopened)
		stored := serving.storedIDs(protocol.Events)
		for sequence, id := range admitted {
			if _, still := left[sequence]; !still && !slices.Contains(stored, id) {
				t.Fatalf("round %d: the spool settled %s, which the platform does not hold", round, id)
			}
		}
		if kept := outstanding(reopened, spool.Events); kept.Lost+kept.Quarantined+kept.Expired != 0 {
			t.Fatalf("round %d: the spool counts %+v", round, kept)
		}
		if err := reopened.Close(); err != nil {
			t.Fatalf("round %d: close the spool: %v", round, err)
		}
	}

	serving.set(nil)
	held := spoolIn(t, directory)
	deliver(t, held, serving, holding, nil)
	eventually(t, "delivering the last of the records", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	want := make([]string, 0, len(admitted))
	for _, id := range admitted {
		want = append(want, id)
	}
	slices.Sort(want)
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, want) || len(serving.conflicting()) != 0 {
		t.Fatalf("the platform stores %d records of the %d admitted, conflicts %v", len(stored), len(want), serving.conflicting())
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != uint64(len(admitted)) {
		t.Fatalf("the spool counts %+v for %d records admitted", kept, len(admitted))
	}
}

func outstandingIDs(t *testing.T, held *spool.Spool) map[uint64]string {
	t.Helper()
	left := map[uint64]string{}
	for from := uint64(1); ; {
		entries, err := held.Read(spool.Events, from, 256, 64<<20)
		if err != nil {
			t.Fatalf("read the spool: %v", err)
		}
		if len(entries) == 0 {
			return left
		}
		for _, entry := range entries {
			left[entry.Sequence] = entry.ID
		}
		from = entries[len(entries)-1].Sequence + 1
	}
}
