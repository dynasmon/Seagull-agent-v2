package compatibility_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

const (
	issuanceRoute = "POST /v1/agents/{id}/certificate"
	renewalRoute  = "POST /v1/agents/certificate"
)

// Each issuance.json under testdata was recorded from the control plane of one
// platform commit, driven by that commit's own harness: the agent's binary made
// every certificate request, an operator's session had the platform answer it,
// and the agent's binary imported what it issued. The bytes of every request
// and answer were kept, with the authority the agent was configured to trust.
type issuanceRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt time.Time          `json:"recorded_at"`
	Authority  string             `json:"authority"`
	Exchanges  []issuanceExchange `json:"exchanges"`
}

type issuanceExchange struct {
	Name    string `json:"name"`
	Route   string `json:"route"`
	AgentID string `json:"agent_id"`
	Status  int    `json:"status"`
}

func TestTheAgentActivatesWhatARecordedPlatformIssuedForItsRequest(t *testing.T) {
	for _, recorded := range issuanceRecordings(t) {
		t.Run(filepath.Base(recorded.directory), func(t *testing.T) {
			issued := 0
			for _, sent := range recorded.Exchanges {
				if sent.Status != http.StatusCreated {
					continue
				}
				requested := recorded.request(t, sent)
				verified, err := enrollment.Verify(recorded.payload(t, sent.Name, "reply"),
					enrollment.Expected{AgentID: sent.AgentID, KeyID: keyOf(requested)}, recorded.authorities(t), recorded.RecordedAt)
				if err != nil {
					t.Fatalf("%s: the agent refused what the platform issued for its request: %v", sent.Name, err)
				}
				if verified.Certificate.Subject != sent.AgentID || !slices.ContainsFunc(verified.Published, recorded.authorities(t)[0].Equal) {
					t.Fatalf("%s: verified %+v, publishing %d authorities", sent.Name, verified.Certificate, len(verified.Published))
				}
				if sent.Route == issuanceRoute {
					issued++
				}
			}
			if issued == 0 {
				t.Fatalf("%s never issued a certificate from a request the agent made", recorded.Platform.Commit)
			}
		})
	}
}

// A request carries the agent it asks to be and the public half of a key, and
// the platform signs it; one the agent makes today has to be the same request,
// or the recording no longer says anything about it.
func TestTheRecordedRequestsAreTheOnesTheAgentMakesAndHoldNoKey(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	defer root.Close()
	keys, err := pki.OpenKeyFiles(root)
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	key, err := keys.Create()
	if err != nil {
		t.Fatalf("create a key: %v", err)
	}
	for _, recorded := range issuanceRecordings(t) {
		for _, sent := range recorded.Exchanges {
			t.Run(filepath.Base(recorded.directory)+"/"+sent.Name, func(t *testing.T) {
				requested := recorded.request(t, sent)
				made, err := pki.Request(key, requested.Subject.CommonName)
				if err != nil {
					t.Fatalf("make a request today: %v", err)
				}
				today := parsed(t, made)
				switch {
				case requested.CheckSignature() != nil:
					t.Fatal("the recorded request is not signed by the key it carries")
				case !bytes.Equal(requested.RawSubject, today.RawSubject):
					t.Fatalf("the recorded request asks to be %s, today's %s", requested.Subject, today.Subject)
				case requested.SignatureAlgorithm != today.SignatureAlgorithm || requested.PublicKeyAlgorithm != today.PublicKeyAlgorithm:
					t.Fatalf("the recorded request is signed with %s over a %s key, today's with %s over %s",
						requested.SignatureAlgorithm, requested.PublicKeyAlgorithm, today.SignatureAlgorithm, today.PublicKeyAlgorithm)
				case len(requested.Extensions) > 0 || len(today.Extensions) > 0 || len(requested.Attributes) > 0 || len(today.Attributes) > 0:
					t.Fatal("a request asks for more than the agent it names")
				}
				if content := recorded.payload(t, sent.Name, "request"); bytes.Contains(content, []byte("PRIVATE KEY")) {
					t.Fatal("the recorded request carries a key")
				}
			})
		}
	}
}

// The platform issues a certificate only for the agent the operator names, and
// only while it registers and admits that agent: the recordings show requests
// the agent made refused for another agent, for an agent never registered and
// for one revoked, whatever the operator's session could do.
func TestARecordedPlatformIssuesNothingForAnAgentItDoesNotRegisterAndAdmit(t *testing.T) {
	cases := map[string]struct {
		status int
		code   string
	}{
		"issuance-other-agent":  {status: http.StatusUnprocessableEntity, code: "malformed_certificate_request"},
		"issuance-unregistered": {status: http.StatusNotFound, code: "unknown_agent"},
		"issuance-revoked":      {status: http.StatusUnprocessableEntity, code: "illegal_move"},
	}
	for _, recorded := range issuanceRecordings(t) {
		for name, want := range cases {
			t.Run(filepath.Base(recorded.directory)+"/"+name, func(t *testing.T) {
				index := slices.IndexFunc(recorded.Exchanges, func(sent issuanceExchange) bool { return sent.Name == name })
				if index < 0 {
					t.Fatalf("recorded no %s exchange", name)
				}
				sent := recorded.Exchanges[index]
				if asked := recorded.request(t, sent).Subject.CommonName; (asked == sent.AgentID) == (name == "issuance-other-agent") {
					t.Fatalf("the request sent for %s asks to be %s", sent.AgentID, asked)
				}
				var refusal controlv1.Refusal
				if err := proto.Unmarshal(recorded.payload(t, sent.Name, "reply"), &refusal); err != nil {
					t.Fatalf("decode the refusal: %v", err)
				}
				if sent.Status != want.status || refusal.GetCode() != want.code {
					t.Fatalf("the platform answered %d %q, want %d %q", sent.Status, refusal.GetCode(), want.status, want.code)
				}
			})
		}
	}
}

func issuanceRecordings(t *testing.T) []issuanceRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "issuance.json"))
	if err != nil {
		t.Fatalf("find the recorded issuance: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("no platform was recorded issuing a certificate, so the agent has nothing to claim it enrolls with")
	}
	found := make([]issuanceRecording, 0, len(manifests))
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := issuanceRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		if recorded.Platform.Commit == "" || recorded.Platform.Contracts == "" || recorded.RecordedAt.IsZero() || recorded.Authority == "" {
			t.Fatalf("%s does not say which platform, contracts, moment and authority it was recorded with", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func (r issuanceRecording) payload(t *testing.T, name, part string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(r.directory, name+"."+part+".pb"))
	if err != nil {
		t.Fatalf("read the %s of %s: %v", part, name, err)
	}
	return encoded
}

func (r issuanceRecording) authorities(t *testing.T) []*x509.Certificate {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(r.directory, r.Authority))
	if err != nil {
		t.Fatalf("read the authority the agent trusted: %v", err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("the recorded authority is not PEM")
	}
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the recorded authority: %v", err)
	}
	return []*x509.Certificate{authority}
}

func (r issuanceRecording) request(t *testing.T, sent issuanceExchange) *x509.CertificateRequest {
	t.Helper()
	switch sent.Route {
	case issuanceRoute:
		var asked agentv1.CertificateRequest
		unmarshal(t, r.payload(t, sent.Name, "request"), &asked)
		if asked.GetExpectedRevision() != 0 {
			t.Fatalf("%s acts on revision %d", sent.Name, asked.GetExpectedRevision())
		}
		return parsed(t, asked.GetCsrPem())
	case renewalRoute:
		var asked agentv1.RenewalRequest
		unmarshal(t, r.payload(t, sent.Name, "request"), &asked)
		return parsed(t, asked.GetCsrPem())
	}
	t.Fatalf("%s was sent to %s, where nothing issues a certificate", sent.Name, sent.Route)
	return nil
}

func parsed(t *testing.T, requested []byte) *x509.CertificateRequest {
	t.Helper()
	block, rest := pem.Decode(requested)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) > 0 {
		t.Fatalf("%q is not one PEM certificate request", requested)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse the certificate request: %v", err)
	}
	return request
}

func keyOf(requested *x509.CertificateRequest) string {
	digest := sha256.Sum256(requested.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(digest[:])
}
