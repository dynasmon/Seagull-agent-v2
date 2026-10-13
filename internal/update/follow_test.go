package update_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// A platform that hands over one offer and the packages it holds, answering a
// package request with a failure as many times as it is told to first.
type platform struct {
	mu       sync.Mutex
	offer    []byte
	packages map[string][]byte
	failing  int
	asked    []string
}

func (p *platform) Get(_ context.Context, request transport.Request) (transport.Reply, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	target, err := url.Parse(request.URL)
	if err != nil {
		return transport.Reply{}, err
	}
	p.asked = append(p.asked, target.Path)
	if target.Path == update.Path {
		tag := strconv.Quote(hex.EncodeToString(digest(p.offer)))
		if request.Unchanged == tag {
			return transport.Reply{Status: http.StatusNotModified, Tag: tag}, nil
		}
		return transport.Reply{Status: http.StatusOK, Body: p.offer, Tag: tag}, nil
	}
	if p.failing > 0 {
		p.failing--
		return transport.Reply{Status: http.StatusServiceUnavailable}, nil
	}
	content, held := p.packages[strings.TrimPrefix(target.Path, update.PackagesPath)]
	if !held {
		return transport.Reply{Status: http.StatusNotFound}, nil
	}
	if int64(len(content)) > request.Most {
		return transport.Reply{}, transport.ErrReplyTooLarge
	}
	if _, err := request.Into.Write(content); err != nil {
		return transport.Reply{}, err
	}
	return transport.Reply{Status: http.StatusOK}, nil
}

func digest(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}

type followed struct {
	follower  *update.Follower
	platform  *platform
	staged    *os.Root
	installer *os.Root
	held      *os.Root
	log       *bytes.Buffer
}

func (e estate) follow(t *testing.T, version string, catalog *updatev1.Catalog, packages map[string][]byte) *followed {
	t.Helper()
	offer, err := proto.Marshal(e.offer(t, version, catalog))
	if err != nil {
		t.Fatal(err)
	}
	held := &followed{
		platform:  &platform{offer: offer, packages: map[string][]byte{}},
		staged:    directory(t),
		installer: directory(t),
		held:      directory(t),
		log:       &bytes.Buffer{},
	}
	for _, content := range packages {
		held.platform.packages[hex.EncodeToString(digest(content))] = content
	}
	store, err := update.OpenStore(held.held)
	if err != nil {
		t.Fatal(err)
	}
	held.follower, err = update.NewFollower(update.Options{
		Client:  held.platform,
		URL:     "https://control.example:8446",
		Anchor:  e.anchor,
		Store:   store,
		Staging: update.OpenStaging(held.staged),
		Journal: func() (update.Journal, bool, error) { return update.ReadJournal(held.installer) },
		Running: running("v0.2.0"),
		Every:   func() time.Duration { return 15 * time.Minute },
		Watch:   10 * time.Millisecond,
		Policy:  link.Policy{Retry: time.Second, RetryLongest: time.Minute, Hold: time.Minute, HoldLongest: time.Hour},
		Logger:  slog.New(slog.NewJSONHandler(held.log, nil)),
		Now:     func() time.Time { return written },
	})
	if err != nil {
		t.Fatalf("follow: %v", err)
	}
	return held
}

func pair(t *testing.T) (current, next []byte, catalog *updatev1.Catalog) {
	t.Helper()
	current, next = []byte("!<arch>\nthe package of v0.2.0"), []byte("!<arch>\nthe package of v0.3.0")
	return current, next, catalogOf(7, releaseFor("v0.2.0", current), releaseFor("v0.3.0", next))
}

func TestAnAgentStagesTheReleaseItIsAskedForBesideTheOneItRuns(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "v0.3.0", catalog, map[string][]byte{"current": current, "next": next})

	if wait := followed.follower.Ask(t.Context()); wait < 12*time.Minute || wait > 18*time.Minute {
		t.Fatalf("the agent waits %s to ask again", wait)
	}
	state := followed.follower.State()
	if state.Stage != update.Staged || state.Version != "v0.3.0" || state.Catalog != 7 || state.Failure != "" {
		t.Fatalf("the agent stands at %+v", state)
	}
	staging := update.OpenStaging(followed.staged)
	offer, err := staging.Offer()
	if !staging.Ready() || err != nil || !bytes.Equal(offer, followed.platform.offer) {
		t.Fatalf("the offer was not handed over as it arrived: %v", err)
	}
	for _, content := range [][]byte{current, next} {
		kept, err := os.ReadFile(filepath.Join(followed.staged.Name(), update.PackageName(digest(content))))
		if err != nil || !bytes.Equal(kept, content) {
			t.Fatalf("a package was staged as %q: %v", kept, err)
		}
	}
	store, _ := update.OpenStore(followed.held)
	if held, err := store.Held(land.anchor, written); err != nil || held.Catalog != 7 {
		t.Fatalf("the agent keeps catalog %d: %v", held.Catalog, err)
	}

	followed.follower.Ask(t.Context())
	if downloads := strings.Count(strings.Join(followed.platform.asked, " "), update.PackagesPath); downloads != 2 {
		t.Fatalf("asking again while the installer had not taken what was staged downloaded %d packages", downloads)
	}
}

func TestAnAgentWaitsForTheInstallerAndSaysWhatItDoes(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "v0.3.0", catalog, map[string][]byte{"current": current, "next": next})
	if err := update.KeepJournal(followed.installer, update.Journal{Stage: update.Checking, Version: "v0.3.0", Catalog: 7, Since: written}); err != nil {
		t.Fatal(err)
	}

	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.Checking || state.Version != "v0.3.0" || len(entries(t, followed.staged)) != 0 {
		t.Fatalf("while the installer checked a release the agent stood at %+v and staged %v", state, entries(t, followed.staged))
	}
}

func TestAnAgentSaysHowTheInstallerEndedAsSoonAsItEndsWithoutAskingAgain(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "v0.3.0", catalog, map[string][]byte{"current": current, "next": next})
	if err := update.KeepJournal(followed.installer, update.Journal{Stage: update.Checking, Version: "v0.3.0", Catalog: 7, Since: written}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- followed.follower.Run(ctx) }()
	standsAt := func(stage update.Stage) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); followed.follower.State().Stage != stage; {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("the agent stands at %+v, and the installer's journal is at %s", followed.follower.State(), stage)
			}
			time.Sleep(time.Millisecond)
		}
	}
	standsAt(update.Checking)
	if err := update.KeepJournal(followed.installer, update.Journal{Stage: update.RolledBack, Version: "v0.3.0", Catalog: 7, Since: written,
		Failure: update.Unhealthy, Reason: "it did not run as it should"}); err != nil {
		t.Fatal(err)
	}
	standsAt(update.RolledBack)
	cancel()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if len(followed.platform.asked) != 1 {
		t.Fatalf("while the installer worked the agent asked the platform for %v", followed.platform.asked)
	}
}

func TestAReleaseTheAgentMayNotInstallIsReportedAndNothingIsFetched(t *testing.T) {
	land := newEstate(t)
	current, _, _ := pair(t)
	older := releaseFor("v0.1.0", []byte("an older package"))
	followed := land.follow(t, "v0.1.0", catalogOf(7, releaseFor("v0.2.0", current), older), nil)

	followed.follower.Ask(t.Context())
	state := followed.follower.State()
	if state.Stage != update.Failed || state.Failure != update.Refused || !strings.Contains(state.Reason, "does not replace") || len(entries(t, followed.staged)) != 0 {
		t.Fatalf("a downgrade it may not take left the agent at %+v", state)
	}
	if !strings.Contains(followed.log.String(), `"msg":"update_failed"`) {
		t.Errorf("the refusal was not logged: %s", followed.log)
	}
}

func TestAPackageThePlatformDidNotHandOverIsAskedForAgain(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "v0.3.0", catalog, map[string][]byte{"current": current, "next": next})
	followed.platform.failing = 1

	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.Downloading || state.Failure != update.Unreachable || update.OpenStaging(followed.staged).Ready() {
		t.Fatalf("a package the platform did not hand over left the agent at %+v", state)
	}
	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.Staged || state.Failure != "" {
		t.Fatalf("asking again left the agent at %+v", state)
	}
}

func TestAPackageThatIsNotTheReleasesIsNeverStaged(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "v0.3.0", catalog, map[string][]byte{"current": current})
	followed.platform.packages[hex.EncodeToString(digest(next))] = bytes.Repeat([]byte("x"), len(next))

	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.Failed || state.Failure != update.Unverified || update.OpenStaging(followed.staged).Ready() {
		t.Fatalf("a package that is not the release's left the agent at %+v", state)
	}
}

func TestAReleaseTheInstallerGaveUpOnIsTriedAgainOnlyUnderANewerCatalog(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "v0.3.0", catalog, map[string][]byte{"current": current, "next": next})
	if err := update.KeepJournal(followed.installer, update.Journal{Stage: update.RolledBack, Version: "v0.3.0", Catalog: 7, Since: written,
		Failure: update.Unhealthy, Reason: "it did not run as it should"}); err != nil {
		t.Fatal(err)
	}

	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.RolledBack || state.Failure != update.Unhealthy || len(entries(t, followed.staged)) != 0 {
		t.Fatalf("a release the installer went back from was tried again under the same catalog: %+v", state)
	}

	catalog.Version = 8
	offer, err := proto.Marshal(land.offer(t, "v0.3.0", catalog))
	if err != nil {
		t.Fatal(err)
	}
	followed.platform.mu.Lock()
	followed.platform.offer = offer
	followed.platform.mu.Unlock()
	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.Staged || state.Catalog != 8 {
		t.Fatalf("a newer catalog did not try the release again: %+v", state)
	}
}

func TestAnAgentThatCannotAskWaitsAndSaysSo(t *testing.T) {
	land := newEstate(t)
	followed := land.follow(t, "", nil, nil)
	failing := &failingClient{}
	follower, err := update.NewFollower(update.Options{
		Client: failing, URL: "https://control.example:8446", Anchor: land.anchor,
		Store: func() *update.Store { store, _ := update.OpenStore(followed.held); return store }(), Staging: update.OpenStaging(followed.staged),
		Journal: func() (update.Journal, bool, error) { return update.ReadJournal(followed.installer) },
		Running: running("v0.2.0"), Every: func() time.Duration { return 15 * time.Minute },
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), Now: func() time.Time { return written },
	})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if wait := follower.Ask(t.Context()); wait <= 0 || wait > 5*time.Minute {
			t.Fatalf("attempt %d waits %s", attempt, wait)
		}
	}
	if state := follower.State(); state.Asking != "failing" || state.Attempts != 2 || state.Stage != "" {
		t.Fatalf("an agent that could not ask stands at %+v", state)
	}
}

type failingClient struct{}

func (failingClient) Get(context.Context, transport.Request) (transport.Reply, error) {
	return transport.Reply{}, transport.ErrUnreachable
}

func TestAnAgentAskedForNothingSaysHowItsLastUpdateEnded(t *testing.T) {
	land := newEstate(t)
	followed := land.follow(t, "", nil, nil)
	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != "" || state.Version != "" {
		t.Fatalf("an agent asked for nothing stands at %+v", state)
	}
	if err := update.KeepJournal(followed.installer, update.Journal{Stage: update.Installed, Version: "v0.2.0", Catalog: 7, Since: written}); err != nil {
		t.Fatal(err)
	}
	followed.platform.mu.Lock()
	followed.platform.offer = nil
	followed.platform.mu.Unlock()
	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Stage != update.Installed || state.Version != "v0.2.0" {
		t.Fatalf("an agent whose last update ended installed stands at %+v", state)
	}
}

func TestAnAgentSaysTheNewestRootAndCatalogItVerifiedWhateverItWasAsked(t *testing.T) {
	land := newEstate(t)
	current, next, catalog := pair(t)
	followed := land.follow(t, "", catalog, map[string][]byte{"current": current, "next": next})
	if state := followed.follower.State(); state.Trusted != 1 || state.Verified != 0 {
		t.Fatalf("before asking the agent says it trusts root %d and verified catalog %d", state.Trusted, state.Verified)
	}

	offer := land.offer(t, "", catalog)
	offer.Roots = append(offer.Roots, sign(t, rootOf(2, []signer{land.owner}, 1, []signer{land.owner}, 1), update.RootPayloadType, land.owner))
	encoded, err := proto.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	followed.platform.offer = encoded
	followed.follower.Ask(t.Context())
	if state := followed.follower.State(); state.Trusted != 2 || state.Verified != 7 || state.Stage != "" {
		t.Fatalf("after an offer asking nothing the agent stands at %+v", state)
	}

	store, err := update.OpenStore(followed.held)
	if err != nil {
		t.Fatal(err)
	}
	again, err := update.NewFollower(update.Options{
		Client:  followed.platform,
		URL:     "https://control.example:8446",
		Anchor:  land.anchor,
		Store:   store,
		Staging: update.OpenStaging(followed.staged),
		Journal: func() (update.Journal, bool, error) { return update.ReadJournal(followed.installer) },
		Running: running("v0.2.0"),
		Every:   func() time.Duration { return 15 * time.Minute },
		Logger:  slog.New(slog.DiscardHandler),
		Now:     func() time.Time { return written },
	})
	if err != nil {
		t.Fatal(err)
	}
	if state := again.State(); state.Trusted != 2 || state.Verified != 7 {
		t.Fatalf("an agent that started again says it trusts root %d and verified catalog %d", state.Trusted, state.Verified)
	}
}
