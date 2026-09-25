package compatibility_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

// Each renewal.json under testdata was recorded from the renewal handler of one
// platform commit, served as its own control plane serves it and backed by that
// commit's harness: the agent's binary renewed its credential while the
// platform rotated its authority and then revoked the agent, and the bytes of
// every renewal and answer were kept with what the agent said of each.
type renewalRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt  time.Time `json:"recorded_at"`
	Authorities struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	} `json:"authorities"`
	Checked   string            `json:"checked"`
	Exchanges []renewalExchange `json:"exchanges"`
}

type renewalExchange struct {
	Name      string `json:"name"`
	Route     string `json:"route"`
	AgentID   string `json:"agent_id"`
	Status    int    `json:"status"`
	Presented string `json:"presented_key_id"`
	Said      string `json:"agent_said"`
}

func TestTheAgentActivatesWhatARecordedPlatformRenewedItsCredentialWith(t *testing.T) {
	for _, recorded := range renewalRecordings(t) {
		renewed := 0
		for _, sent := range recorded.Exchanges {
			if sent.Status != http.StatusCreated {
				continue
			}
			t.Run(filepath.Base(recorded.directory)+"/"+sent.Name, func(t *testing.T) {
				reply := recorded.payload(t, sent.Name, "reply")
				published, err := enrollment.Published(reply)
				if err != nil {
					t.Fatalf("read the authorities the answer published: %v", err)
				}
				requested := recorded.request(t, sent)
				verified, err := enrollment.Verify(reply, enrollment.Expected{AgentID: sent.AgentID, KeyID: keyOf(requested)}, published, recorded.RecordedAt)
				if err != nil {
					t.Fatalf("the agent refused what the platform renewed its credential with: %v", err)
				}
				if verified.Certificate.Subject != sent.AgentID || requested.Subject.CommonName != sent.AgentID {
					t.Fatalf("renewed %s with a request for %s", verified.Certificate.Subject, requested.Subject.CommonName)
				}
				if requested.CheckSignature() != nil || requested.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(requested.Extensions) > 0 || len(requested.Attributes) > 0 ||
					bytes.Contains(recorded.payload(t, sent.Name, "request"), []byte("PRIVATE KEY")) {
					t.Fatal("the renewal asked for more than the agent and its public key, or carried a key")
				}
			})
			renewed++
		}
		if renewed == 0 {
			t.Fatalf("%s never renewed a credential the agent presented", recorded.Platform.Commit)
		}
	}
}

func TestARecordedRenewalKeepsOrRotatesTheKeyAsTheAgentDecided(t *testing.T) {
	for _, recorded := range renewalRecordings(t) {
		kept, rotated := recorded.exchange(t, "renewal-kept"), recorded.exchange(t, "renewal-rotated")
		if keyOf(recorded.request(t, kept)) != kept.Presented {
			t.Errorf("a renewal that kept its key asked for another one")
		}
		drawn := keyOf(recorded.request(t, rotated))
		if drawn == rotated.Presented {
			t.Errorf("a renewal that rotated its key asked for the key it presented")
		}
		if next := recorded.exchange(t, "renewal-overlap"); next.Presented != drawn {
			t.Errorf("after rotating, the agent presented key %s rather than the one it drew, %s", next.Presented, drawn)
		}
	}
}

// The four steps the platform rotates its authority in: publish the next one
// beside the current, sign with the next, retire the current, and serve the
// listener from the next. The agent trusts each set from the renewal that
// brought it, except the one that would not authenticate the listener that
// published it, and once the current authority is retired it no longer
// authenticates a listener that still presents one of its certificates.
func TestARecordedPlatformRotatedItsAuthorityWithoutStrandingTheAgent(t *testing.T) {
	for _, recorded := range renewalRecordings(t) {
		current, next := recorded.authority(t, recorded.Authorities.Current), recorded.authority(t, recorded.Authorities.Next)
		steps := []struct {
			name      string
			published []*x509.Certificate
			issuer    *x509.Certificate
			said      string
		}{
			{name: "renewal-kept", published: []*x509.Certificate{current}, issuer: current},
			{name: "renewal-overlap", published: []*x509.Certificate{current, next}, issuer: current, said: "against the 2 authorities the platform published from now on"},
			{name: "renewal-next-authority", published: []*x509.Certificate{current, next}, issuer: next},
			{name: "renewal-not-adopted", published: []*x509.Certificate{next}, issuer: next, said: renewal.ErrNotAdoptable.Error()},
			{name: "renewal-removal", published: []*x509.Certificate{next}, issuer: next, said: "against the 1 authority the platform published from now on"},
		}
		for _, step := range steps {
			t.Run(filepath.Base(recorded.directory)+"/"+step.name, func(t *testing.T) {
				sent := recorded.exchange(t, step.name)
				var answer agentv1.IssuedCertificate
				unmarshal(t, recorded.payload(t, sent.Name, "reply"), &answer)
				published, err := enrollment.Published(recorded.payload(t, sent.Name, "reply"))
				if err != nil || !slices.EqualFunc(published, step.published, (*x509.Certificate).Equal) {
					t.Fatalf("the platform published %d authorities: %v", len(published), err)
				}
				block, _ := pem.Decode(answer.GetCertificatePem())
				leaf, err := x509.ParseCertificate(block.Bytes)
				if err != nil || leaf.CheckSignatureFrom(step.issuer) != nil {
					t.Fatalf("the certificate was not issued by %s: %v", step.issuer.Subject.CommonName, err)
				}
				if step.said != "" && !strings.Contains(sent.Said, step.said) {
					t.Fatalf("the agent said %q", sent.Said)
				}
			})
		}
		if !strings.Contains(recorded.Checked, "ingest: the platform could not be authenticated") || !strings.Contains(recorded.Checked, "is authenticated") {
			t.Errorf("after the rotation the agent checked the platform as:\n%s", recorded.Checked)
		}
	}
}

func TestARecordedPlatformStillRenewsAGenerationARenewalReplaced(t *testing.T) {
	for _, recorded := range renewalRecordings(t) {
		superseded, kept := recorded.exchange(t, "renewal-superseded"), recorded.exchange(t, "renewal-kept")
		if superseded.Status != http.StatusCreated || superseded.Presented != kept.Presented {
			t.Errorf("the platform answered the generation two renewals replaced with %d", superseded.Status)
		}
	}
}

func TestARecordedPlatformRenewsNoAgentItRevoked(t *testing.T) {
	for _, recorded := range renewalRecordings(t) {
		sent := recorded.exchange(t, "renewal-revoked")
		var refused controlv1.Refusal
		unmarshal(t, recorded.payload(t, sent.Name, "reply"), &refused)
		read := &renewal.Refusal{Status: sent.Status, Code: refused.GetCode(), Detail: refused.GetDetail()}
		if sent.Status != http.StatusUnprocessableEntity || refused.GetCode() != "illegal_move" || !renewal.Lasting(read) {
			t.Errorf("the platform answered a revoked agent with %d %q", sent.Status, refused.GetCode())
		}
		if !strings.Contains(sent.Said, "the agent never enrolls itself again") {
			t.Errorf("a revoked agent said %q", sent.Said)
		}
	}
}

// How long the recorded platform takes to stop admitting an agent it revoked:
// from its control plane publishing the revocation to the roster its gateway
// follows refusing the agent, measured over the platform's own publisher,
// reader and roster against a broker of the version its deployment runs.
func TestTheRecordedPlatformsRevocationPropagationWasMeasured(t *testing.T) {
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "revocation.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no revocation propagation was measured: %v", err)
	}
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		var measured struct {
			Platform     map[string]string `json:"platform"`
			MeasuredAt   time.Time         `json:"measured_at"`
			Revocations  int               `json:"revocations"`
			Measured     string            `json:"measured"`
			Propagation  map[string]string `json:"propagation"`
			Acknowledged map[string]string `json:"acknowledged"`
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&measured); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		var previous time.Duration
		for _, share := range []string{"p50", "p95", "p99", "max"} {
			took, err := time.ParseDuration(measured.Propagation[share])
			if err != nil || took < previous {
				t.Fatalf("%s says the %s of propagation is %q", manifest, share, measured.Propagation[share])
			}
			previous = took
		}
		if measured.Revocations < 100 || measured.Platform["commit"] == "" || measured.MeasuredAt.IsZero() {
			t.Fatalf("%s measured %d revocations of %v", manifest, measured.Revocations, measured.Platform)
		}
	}
}

func renewalRecordings(t *testing.T) []renewalRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "renewal.json"))
	if err != nil {
		t.Fatalf("find the recorded renewals: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("no platform was recorded renewing a credential, so the agent has nothing to claim it renews with")
	}
	found := make([]renewalRecording, 0, len(manifests))
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := renewalRecording{directory: filepath.Dir(manifest)}
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

func (r renewalRecording) exchange(t *testing.T, name string) renewalExchange {
	t.Helper()
	index := slices.IndexFunc(r.Exchanges, func(sent renewalExchange) bool { return sent.Name == name })
	if index < 0 {
		t.Fatalf("%s recorded no %s exchange", filepath.Base(r.directory), name)
	}
	return r.Exchanges[index]
}

func (r renewalRecording) payload(t *testing.T, name, part string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(r.directory, name+"."+part+".pb"))
	if err != nil {
		t.Fatalf("read the %s of %s: %v", part, name, err)
	}
	return encoded
}

func (r renewalRecording) request(t *testing.T, sent renewalExchange) *x509.CertificateRequest {
	t.Helper()
	if sent.Route != renewalRoute {
		t.Fatalf("%s was sent to %s, where the agent renews nothing", sent.Name, sent.Route)
	}
	var asked agentv1.RenewalRequest
	if err := proto.Unmarshal(r.payload(t, sent.Name, "request"), &asked); err != nil {
		t.Fatalf("decode the renewal: %v", err)
	}
	return parsed(t, asked.GetCsrPem())
}

func (r renewalRecording) authority(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(r.directory, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatalf("%s is not PEM", name)
	}
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return authority
}
