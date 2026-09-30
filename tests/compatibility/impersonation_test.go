package compatibility_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// Each impersonation.json under testdata was recorded from the ingest gateway
// of one platform commit, driven by that commit's own end-to-end harness:
// records claiming another registered agent and its tenant, sent under the
// certificate of an agent with headers claiming the same; that agent's
// certificate presented with a key it was not issued for; and one certificate
// and key held twice, sent from both holders before and after the platform
// revoked the agent. Beside each request and answer is what the gateway put on
// its backbone.
type impersonationRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt time.Time               `json:"recorded_at"`
	Exchanges  []impersonationExchange `json:"exchanges"`
}

type impersonationExchange struct {
	Name        string            `json:"name"`
	Route       string            `json:"route"`
	Certificate string            `json:"certificate"`
	Registered  string            `json:"registered"`
	Holder      string            `json:"holder"`
	Presented   string            `json:"presented_certificate"`
	Key         string            `json:"presented_key"`
	Headers     map[string]string `json:"headers"`
	Status      int               `json:"status"`
	ContentType string            `json:"content_type"`
	Refused     string            `json:"refused"`
	Published   int               `json:"published"`
}

// The platform takes the agent from the certificate it verified and the tenant
// from its registration of that agent, and replaces what the platform alone
// writes whatever a batch or a header claims: the records it published name the
// agent that connected and are otherwise what the agent sent, the host it
// observed included.
func TestARecordedPlatformNamesTheAgentItAuthenticatedWhateverTheBatchClaims(t *testing.T) {
	for _, recorded := range impersonationRecordings(t) {
		for _, name := range []string{"events-forged-origin", "inventory-forged-origin"} {
			t.Run(recorded.name()+"/"+name, func(t *testing.T) {
				sent := recorded.exchange(t, name)
				claimed := slices.Collect(func(yield func(string) bool) {
					for _, value := range sent.Headers {
						yield(value)
					}
				})
				if !slices.ContainsFunc(claimed, func(value string) bool { return value != sent.Certificate && value != sent.Registered }) {
					t.Fatalf("the batch was sent with headers %v, which claim nothing but the certificate", sent.Headers)
				}
				carried := routeOf(t, sent.Route)
				request := recorded.payload(t, name, "request")
				verdict := carried.Judge(sentAt(carried.Records(request), recorded.RecordedAt),
					protocol.Answer{Status: sent.Status, ContentType: sent.ContentType, Body: recorded.payload(t, name, "reply")})
				if verdict.Outcome != protocol.Durable {
					t.Fatalf("the agent reads the answer as %v", verdict)
				}
				asked, kept := originsOf(t, carried, request), originsOf(t, carried, recorded.payload(t, name, "published"))
				if len(kept) != sent.Published || len(kept) != len(asked) {
					t.Fatalf("the platform published %d of %d records", len(kept), len(asked))
				}
				for index := range asked {
					if asked[index].origin.GetAgentId() == sent.Certificate || asked[index].origin.GetTenantId() == sent.Registered || asked[index].reception == nil {
						t.Fatalf("record %d claims %v, which forges nothing", index, asked[index].origin)
					}
					if kept[index].origin.GetAgentId() != sent.Certificate || kept[index].origin.GetTenantId() != sent.Registered {
						t.Errorf("record %d, which claimed %s of %s, was published as %s of %s", index, asked[index].origin.GetAgentId(),
							asked[index].origin.GetTenantId(), kept[index].origin.GetAgentId(), kept[index].origin.GetTenantId())
					}
					if proto.Equal(kept[index].reception, asked[index].reception) || kept[index].reception.GetBatchId() != identifier(t, carried, request) {
						t.Errorf("record %d was published with the reception %v it claimed", index, kept[index].reception)
					}
					if !proto.Equal(kept[index].rest, asked[index].rest) || !proto.Equal(kept[index].origin.GetHost(), asked[index].origin.GetHost()) {
						t.Errorf("record %d was published with more changed than the agent and tenant the platform assigns", index)
					}
				}
			})
		}
	}
}

// A certificate is public, and whoever copies one without its key cannot sign
// the handshake as that key: the recorded gateway refused the connection before
// anything reached it, so nothing was published as the agent.
func TestARecordedPlatformRefusesACertificateCopiedWithoutItsKey(t *testing.T) {
	for _, recorded := range impersonationRecordings(t) {
		copied, genuine := recorded.exchange(t, "events-copied-certificate"), recorded.exchange(t, "events-forged-origin")
		if copied.Presented != genuine.Presented || copied.Key == genuine.Key {
			t.Fatalf("%s: the copy presented certificate %s with key %s, and the agent certificate %s with key %s",
				recorded.name(), copied.Presented, copied.Key, genuine.Presented, genuine.Key)
		}
		if copied.Status != 0 || copied.Published != 0 || !strings.HasPrefix(copied.Refused, "remote error: tls:") {
			t.Fatalf("%s: the copied certificate was answered %d, refused with %q and %d records were published",
				recorded.name(), copied.Status, copied.Refused, copied.Published)
		}
	}
}

// Two holders of one certificate and its key are one agent to the platform:
// the recorded gateway answered and published both alike, as the agent the
// certificate names, and nothing it answered tells them apart. Revoking the
// agent refused both, which is the whole of what the platform does about a
// copied key on the ingest path.
func TestARecordedPlatformTellsNoHolderOfACopiedCredentialFromAnother(t *testing.T) {
	for _, recorded := range impersonationRecordings(t) {
		original, copied := recorded.exchange(t, "events-cloned-original"), recorded.exchange(t, "events-cloned-copy")
		if original.Presented != copied.Presented || original.Key != copied.Key || original.Holder == copied.Holder {
			t.Fatalf("%s: the holders presented %s and %s", recorded.name(), original.Presented, copied.Presented)
		}
		for _, sent := range []impersonationExchange{original, copied} {
			carried := routeOf(t, sent.Route)
			request := recorded.payload(t, sent.Name, "request")
			answer := protocol.Answer{Status: sent.Status, ContentType: sent.ContentType, Body: recorded.payload(t, sent.Name, "reply")}
			if verdict := carried.Judge(sentAt(carried.Records(request), recorded.RecordedAt), answer); verdict.Outcome != protocol.Durable {
				t.Fatalf("%s: the %s was answered %v", recorded.name(), sent.Holder, verdict)
			}
			for _, kept := range originsOf(t, carried, recorded.payload(t, sent.Name, "published")) {
				if kept.origin.GetAgentId() != sent.Certificate || kept.origin.GetTenantId() != sent.Registered {
					t.Fatalf("%s: what the %s sent was published as %v", recorded.name(), sent.Holder, kept.origin)
				}
			}
		}
		if !bytes.Equal(recorded.payload(t, original.Name, "reply"), recorded.payload(t, copied.Name, "reply")) {
			t.Errorf("%s: the platform answered the two holders differently", recorded.name())
		}
		for _, name := range []string{"events-cloned-original-revoked", "events-cloned-copy-revoked"} {
			sent := recorded.exchange(t, name)
			var refusal ingestv1.Rejection
			unmarshal(t, recorded.payload(t, name, "reply"), &refusal)
			if exclusion, excluded := protocol.Excluded(&refusal); sent.Status != http.StatusForbidden || !excluded || exclusion.Reason != protocol.Unadmitted || sent.Published != 0 {
				t.Errorf("%s: once the agent was revoked, the %s was answered %d, %v", recorded.name(), sent.Holder, sent.Status, &refusal)
			}
		}
	}
}

type origins struct {
	origin    *eventv1.Origin
	reception *eventv1.Reception
	rest      proto.Message
}

func originsOf(t *testing.T, carried protocol.Route, batch []byte) []origins {
	t.Helper()
	var found []origins
	for _, record := range carried.Records(batch) {
		switch carried {
		case protocol.Events:
			var event eventv1.Event
			unmarshal(t, record, &event)
			held := origins{origin: event.GetOrigin(), reception: event.GetReception()}
			event.Origin, event.Reception = nil, nil
			held.rest = &event
			found = append(found, held)
		case protocol.Inventory:
			var inventory inventoryv1.Record
			unmarshal(t, record, &inventory)
			held := origins{origin: inventory.GetOrigin(), reception: inventory.GetReception()}
			inventory.Origin, inventory.Reception = nil, nil
			held.rest = &inventory
			found = append(found, held)
		}
	}
	return found
}

func sentAt(records [][]byte, admitted time.Time) []protocol.Sent {
	sent := make([]protocol.Sent, 0, len(records))
	for _, record := range records {
		sent = append(sent, protocol.Sent{Record: record, Admitted: admitted})
	}
	return sent
}

func impersonationRecordings(t *testing.T) []impersonationRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "impersonation.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded answering an agent that claims to be another: %v", err)
	}
	var found []impersonationRecording
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := impersonationRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		if recorded.Platform.Commit == "" || recorded.Platform.Contracts == "" || recorded.RecordedAt.IsZero() {
			t.Fatalf("%s does not say which platform, contracts and moment it was recorded with", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func (r impersonationRecording) name() string { return filepath.Base(r.directory) }

func (r impersonationRecording) exchange(t *testing.T, name string) impersonationExchange {
	t.Helper()
	index := slices.IndexFunc(r.Exchanges, func(sent impersonationExchange) bool { return sent.Name == name })
	if index < 0 {
		t.Fatalf("%s recorded no %s exchange", r.name(), name)
	}
	return r.Exchanges[index]
}

func (r impersonationRecording) payload(t *testing.T, name, part string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(r.directory, name+"."+part+".pb"))
	if err != nil {
		t.Fatalf("read the %s of %s: %v", part, name, err)
	}
	return encoded
}
