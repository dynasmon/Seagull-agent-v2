package compatibility_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// Each update.json under testdata was recorded from the listener a platform
// commit hands its agents their updates on, with the root that platform was
// configured with and every agent provisioned with: what each agent asked,
// naming what it held, and the answer it got.
type updateRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt time.Time        `json:"recorded_at"`
	Root       string           `json:"root"`
	Exchanges  []updateExchange `json:"exchanges"`
}

type updateExchange struct {
	Name          string `json:"name"`
	Route         string `json:"route"`
	AgentID       string `json:"agent_id"`
	IfNoneMatch   string `json:"if_none_match"`
	Status        int    `json:"status"`
	ContentType   string `json:"content_type"`
	Tag           string `json:"etag"`
	ContentLength string `json:"content_length"`
}

var updateAnswers = map[string]struct {
	asking string
	stage  update.Stage
}{
	"update-nothing":            {"200", ""},
	"update-offered":            {"200", update.Staged},
	"update-unchanged":          {"304", update.Staged},
	"update-package-target":     {"200", update.Staged},
	"update-package-running":    {"200", update.Staged},
	"update-package-unknown":    {"200", update.Downloading},
	"update-unassigned":         {"200", ""},
	"update-package-unassigned": {"200", update.Downloading},
	"update-not-admitted":       {"403", ""},
	"update-unknown-agent":      {"404", ""},
	"update-unidentified":       {"failing", ""},
	"update-not-configured":     {"404", ""},
	"update-rate-limited":       {"failing", ""},
}

type replayedPlatform struct {
	offer    updateExchange
	refusal  *updateExchange
	recorded updateRecording
	t        *testing.T
	asked    []transport.Request
}

func (p *replayedPlatform) Get(_ context.Context, request transport.Request) (transport.Reply, error) {
	p.asked = append(p.asked, request)
	target, err := url.Parse(request.URL)
	if err != nil {
		return transport.Reply{}, err
	}
	sent := p.offer
	if target.Path != update.Path {
		sent = p.recorded.packageFor(p.t, strings.TrimPrefix(target.Path, update.PackagesPath), p.refusal)
	}
	body := p.recorded.reply(p.t, sent.Name)
	streamed := request.Into != nil && sent.Status == http.StatusOK
	if (streamed || request.Into == nil) && int64(len(body)) > request.Most {
		return transport.Reply{}, transport.ErrReplyTooLarge
	}
	reply := transport.Reply{Status: sent.Status, ContentType: sent.ContentType, Tag: sent.Tag}
	if streamed {
		if _, err := request.Into.Write(body); err != nil {
			return transport.Reply{}, fmt.Errorf("%w: %v", transport.ErrUnwritten, err)
		}
		return reply, nil
	}
	reply.Body = body
	return reply, nil
}

type followedRecording struct {
	follower *update.Follower
	platform *replayedPlatform
	store    *update.Store
	staged   *os.Root
	anchor   *update.Root
}

func (r updateRecording) follow(t *testing.T, anchor *update.Root, platform *replayedPlatform) followedRecording {
	t.Helper()
	open := func() *os.Root {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root
	}
	followed := followedRecording{platform: platform, staged: open(), anchor: anchor}
	var err error
	if followed.store, err = update.OpenStore(open()); err != nil {
		t.Fatal(err)
	}
	version, _ := update.ParseVersion("v0.2.0")
	followed.follower, err = update.NewFollower(update.Options{
		Client:  platform,
		URL:     "https://control.example:8446",
		Anchor:  anchor,
		Store:   followed.store,
		Staging: update.OpenStaging(followed.staged),
		Journal: func() (update.Journal, bool, error) { return update.Journal{}, false, nil },
		Running: update.Running{Version: version, OS: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB, State: update.StateGeneration},
		Every:   func() time.Duration { return time.Hour },
		Policy:  link.Policy{Retry: time.Second, RetryLongest: time.Minute, Hold: time.Minute, HoldLongest: time.Hour},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     func() time.Time { return r.RecordedAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	return followed
}

// An agent provisioned with the root a recorded platform was configured with
// walks the roots it is handed to the newest, verifies the catalog under it,
// and stages exactly the bytes the catalog names for the release it is asked to
// run and the one it runs; asking again naming the offer it holds changes
// nothing, and the installer verifies all of it again as it takes it.
func TestAnAgentStagesWhatARecordedPlatformOffersAndTheInstallerTakesIt(t *testing.T) {
	for _, recorded := range updateRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			platform := &replayedPlatform{recorded: recorded, t: t}
			followed := recorded.follow(t, recorded.anchor(t), platform)
			seen := map[string]bool{}
			for _, sent := range recorded.Exchanges {
				if _, known := updateAnswers[sent.Name]; !known {
					t.Fatalf("nothing says what the agent does after %s", sent.Name)
				}
				seen[sent.Name] = true
			}
			for name := range updateAnswers {
				if !seen[name] {
					t.Errorf("%s recorded no %s exchange", recorded.name(), name)
				}
			}

			for _, name := range []string{"update-nothing", "update-offered", "update-unchanged"} {
				sent := recorded.exchange(t, name)
				platform.offer = sent
				followed.follower.Ask(t.Context())
				asked := platform.asked[len(platform.asked)-1]
				if name == "update-unchanged" && asked.Unchanged != sent.IfNoneMatch {
					t.Fatalf("the agent asked again naming %q, and the platform was asked naming %q", asked.Unchanged, sent.IfNoneMatch)
				}
				state := followed.follower.State()
				if want := updateAnswers[name]; state.Asking != want.asking || state.Stage != want.stage || state.Failure != "" {
					t.Fatalf("after %s the agent stands at %+v", name, state)
				}
			}
			if downloads := len(platform.asked) - 3; downloads != 2 {
				t.Fatalf("the agent downloaded %d packages to stage one release and the one it runs", downloads)
			}
			state := followed.follower.State()
			if state.Version != "v0.3.0" || state.Catalog != 1 || state.Root != 2 {
				t.Fatalf("the agent staged %s of catalog %d under root %d", state.Version, state.Catalog, state.Root)
			}

			staging := update.OpenStaging(followed.staged)
			offered, err := staging.Offer()
			if !staging.Ready() || err != nil || !bytes.Equal(offered, recorded.reply(t, "update-offered")) {
				t.Fatalf("the offer was not handed to the installer as it arrived: %v", err)
			}
			var offer updatev1.Offer
			if err := proto.Unmarshal(offered, &offer); err != nil {
				t.Fatal(err)
			}
			held, err := followed.store.Held(followed.anchor, recorded.RecordedAt)
			if err != nil || held.Root.Version() != 2 || held.Catalog != 1 {
				t.Fatalf("the agent kept root %d and catalog %d: %v", held.Root.Version(), held.Catalog, err)
			}
			installer, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer installer.Close()
			version, _ := update.ParseVersion("v0.2.0")
			judged, err := update.Judge(&offer, update.Held{Root: followed.anchor}, update.Running{
				Version: version, OS: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB, State: update.StateGeneration,
			}, recorded.RecordedAt)
			if err != nil || judged.Target.GetVersion() != "v0.3.0" || judged.Current.GetVersion() != "v0.2.0" {
				t.Fatalf("the installer judged what was staged as %v: %v", judged, err)
			}
			for _, release := range []*updatev1.Release{judged.Target, judged.Current} {
				if err := staging.Take(release, installer); err != nil {
					t.Fatalf("the installer did not take the package of %s: %v", release.GetVersion(), err)
				}
			}
		})
	}
}

// What a recorded platform answers that offers no release leaves the agent
// with nothing to install and nothing to fetch, whether it offers roots and a
// catalog and no version, does not know or no longer admits the agent, hands
// out no update, or refuses how or how often it was asked.
func TestARecordedPlatformThatOffersNothingLeavesAnAgentNothingToInstall(t *testing.T) {
	for _, recorded := range updateRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			for _, name := range []string{"update-unassigned", "update-not-admitted", "update-unknown-agent", "update-unidentified", "update-not-configured", "update-rate-limited"} {
				platform := &replayedPlatform{recorded: recorded, t: t, offer: recorded.exchange(t, name)}
				followed := recorded.follow(t, recorded.anchor(t), platform)
				followed.follower.Ask(t.Context())
				state, want := followed.follower.State(), updateAnswers[name]
				if state.Asking != want.asking || state.Stage != want.stage || len(platform.asked) != 1 || update.OpenStaging(followed.staged).Ready() {
					t.Fatalf("after %s the agent stands at %+v and asked %d times", name, state, len(platform.asked))
				}
			}
		})
	}
}

func TestAPackageARecordedPlatformRefusesIsNeverStaged(t *testing.T) {
	for _, recorded := range updateRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			for _, name := range []string{"update-package-unknown", "update-package-unassigned"} {
				refusal := recorded.exchange(t, name)
				platform := &replayedPlatform{recorded: recorded, t: t, offer: recorded.exchange(t, "update-offered"), refusal: &refusal}
				followed := recorded.follow(t, recorded.anchor(t), platform)
				followed.follower.Ask(t.Context())
				state := followed.follower.State()
				if state.Stage != updateAnswers[name].stage || state.Failure != update.Unreachable || !strings.Contains(state.Reason, "unknown_package") ||
					update.OpenStaging(followed.staged).Ready() {
					t.Fatalf("after %s the agent stands at %+v", name, state)
				}
			}
		})
	}
}

// An agent provisioned with any other root refuses what a recorded platform
// offers: nothing the platform holds signs for a root it was not given.
func TestAnOfferARecordedPlatformMadeVerifiesOnlyUnderTheRootItWasConfiguredWith(t *testing.T) {
	for _, recorded := range updateRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			platform := &replayedPlatform{recorded: recorded, t: t, offer: recorded.exchange(t, "update-offered")}
			followed := recorded.follow(t, strangerRoot(t, recorded.RecordedAt), platform)
			followed.follower.Ask(t.Context())
			if state := followed.follower.State(); state.Stage != update.Failed || state.Failure != update.Unverified || len(platform.asked) != 1 {
				t.Fatalf("an agent provisioned with another root stands at %+v", state)
			}
		})
	}
}

func strangerRoot(t *testing.T, at time.Time) *update.Root {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := update.KeyID(der)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&updatev1.Root{
		SchemaVersion: update.SchemaVersion, Version: 1,
		IssuedAt: timestamppb.New(at.Add(-time.Hour)), ExpiresAt: timestamppb.New(at.Add(24 * time.Hour)),
		Keys: []*updatev1.Key{{Keyid: id, PublicKey: der}},
		Root: &updatev1.Role{Keyids: []string{id}, Threshold: 1}, Catalog: &updatev1.Role{Keyids: []string{id}, Threshold: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(dsse.PAE(update.RootPayloadType, payload))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := proto.Marshal(&updatev1.Envelope{Payload: payload, PayloadType: update.RootPayloadType,
		Signatures: []*updatev1.Signature{{Sig: signature, Keyid: id}}})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := update.Anchor(envelope, at)
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

func updateRecordings(t *testing.T) []updateRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "update.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("no platform was recorded handing an agent its updates")
	}
	found := make([]updateRecording, 0, len(manifests))
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := updateRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		if recorded.Platform.Commit == "" || recorded.Platform.Contracts == "" || recorded.RecordedAt.IsZero() || recorded.Root == "" {
			t.Fatalf("%s does not say which platform, contracts, moment and root it was recorded with", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func (r updateRecording) name() string { return filepath.Base(r.directory) }

func (r updateRecording) reply(t *testing.T, name string) []byte {
	t.Helper()
	held, err := os.ReadFile(filepath.Join(r.directory, name+".reply.pb"))
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func (r updateRecording) exchange(t *testing.T, name string) updateExchange {
	t.Helper()
	index := slices.IndexFunc(r.Exchanges, func(sent updateExchange) bool { return sent.Name == name })
	if index < 0 {
		t.Fatalf("%s recorded no %s exchange", r.name(), name)
	}
	return r.Exchanges[index]
}

func (r updateRecording) packageFor(t *testing.T, digest string, refusal *updateExchange) updateExchange {
	t.Helper()
	if refusal != nil {
		return *refusal
	}
	for _, sent := range r.Exchanges {
		if sent.Status != http.StatusOK || !strings.HasPrefix(sent.Name, "update-package-") {
			continue
		}
		if sum := sha256.Sum256(r.reply(t, sent.Name)); hex.EncodeToString(sum[:]) == digest {
			return sent
		}
	}
	return r.exchange(t, "update-package-unknown")
}

func (r updateRecording) anchor(t *testing.T) *update.Root {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(r.directory, r.Root))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := update.Anchor(content, r.RecordedAt)
	if err != nil {
		t.Fatalf("read the root %s was configured with: %v", r.name(), err)
	}
	return anchor
}
