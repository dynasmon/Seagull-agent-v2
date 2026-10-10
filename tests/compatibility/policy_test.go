package compatibility_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

// Each policy.json under testdata was recorded from the listener a platform
// commit hands its agents their policy on, with the public key the policies
// it served were signed under: what each agent asked, naming what it held,
// and the answer it got.
type policyRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt time.Time        `json:"recorded_at"`
	Signers    string           `json:"signers"`
	Exchanges  []policyExchange `json:"exchanges"`
}

type policyExchange struct {
	Name        string `json:"name"`
	Route       string `json:"route"`
	AgentID     string `json:"agent_id"`
	IfNoneMatch string `json:"if_none_match"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Tag         string `json:"etag"`
}

var answered = map[string]policy.Answer{
	"policy-served":        policy.Served,
	"policy-unchanged":     policy.Unchanged,
	"policy-newer":         policy.Served,
	"policy-none":          policy.NoPolicy,
	"policy-not-admitted":  policy.NotAdmitted,
	"policy-unknown-agent": policy.Unknown,
	"policy-unidentified":  policy.Failing,
}

type replaying struct {
	reply transport.Reply
	asked transport.Request
}

func (r *replaying) Get(_ context.Context, request transport.Request) (transport.Reply, error) {
	r.asked = request
	return r.reply, nil
}

// What the agent makes of every answer a recorded platform gave: a policy it
// verifies under the key the platform's operator signed with and applies over
// its own configuration, a 304 that changes nothing, and refusals that name
// what the platform holds of the agent rather than a policy.
func TestWhatARecordedPlatformHandsAnAgentIsWhatTheAgentApplies(t *testing.T) {
	for _, recorded := range policyRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			verifier := recorded.verifier(t)
			own := ownConfiguration(t)
			var holding policy.Holding
			seen := map[string]bool{}
			for _, sent := range recorded.Exchanges {
				want, known := answered[sent.Name]
				if !known {
					t.Fatalf("nothing says what the agent does after %s", sent.Name)
				}
				seen[sent.Name] = true
				body := recorded.reply(t, sent.Name)
				var offered [][]byte
				client := &replaying{reply: transport.Reply{Status: sent.Status, ContentType: sent.ContentType, Body: body, Tag: sent.Tag}}
				follower, err := policy.New(policy.Options{
					Client:  client,
					URL:     "https://control.example:8446",
					Tag:     func() string { return holding.Digest },
					Offered: func(_ context.Context, served []byte) error { offered = append(offered, served); return nil },
					Every:   func() time.Duration { return time.Hour },
					Policy:  link.Policy{},
					Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
				})
				if err != nil {
					t.Fatal(err)
				}
				follower.Ask(t.Context())
				if got := follower.State().Answer; got != want {
					t.Fatalf("%s was read as %s, want %s", sent.Name, got, want)
				}
				if sent.IfNoneMatch != "" && sent.IfNoneMatch != strconv.Quote(holding.Digest) {
					t.Fatalf("%s was asked naming %s, and the agent held %s", sent.Name, sent.IfNoneMatch, holding.Digest)
				}
				if want != policy.Served {
					if len(offered) != 0 {
						t.Fatalf("%s handed the agent a policy", sent.Name)
					}
					continue
				}
				verified, err := verifier.Verify(offered[0])
				if err != nil {
					t.Fatalf("the agent cannot verify what %s handed it: %v", sent.Name, err)
				}
				if sent.Tag != strconv.Quote(verified.Digest) {
					t.Fatalf("%s tagged the envelope %s, and the agent holds it as %s", sent.Name, sent.Tag, verified.Digest)
				}
				if err := policy.Judge(verified, sent.AgentID, holding, recorded.RecordedAt); err != nil {
					t.Fatalf("the agent refuses what %s handed it: %v", sent.Name, err)
				}
				made, kept, err := policy.Overlay(own, verified.Policy.GetSettings())
				if err != nil {
					t.Fatalf("the agent does not run on what %s sets: %v", sent.Name, err)
				}
				if made.Logging.Level == "" || made.Server != own.Server || made.Identity != own.Identity {
					t.Fatalf("%s reached what no policy reaches: %+v", sent.Name, made)
				}
				for _, ceiling := range kept {
					if ceiling.Own == "" || ceiling.Asked == "" {
						t.Fatalf("%s reports a kept ceiling as %+v", sent.Name, ceiling)
					}
				}
				holding = policy.Holding{Revision: verified.Policy.GetRevision(), Digest: verified.Digest}
			}
			for name := range answered {
				if !seen[name] {
					t.Errorf("%s recorded no %s exchange", recorded.name(), name)
				}
			}
			if holding.Revision < 2 {
				t.Errorf("%s recorded no newer revision the agent applied", recorded.name())
			}
		})
	}
}

func TestAPolicyARecordedPlatformHandsIsSignedOffThePlatform(t *testing.T) {
	for _, recorded := range policyRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			elsewhere, err := policy.NewVerifier([]*ecdsa.PublicKey{&stranger.PublicKey})
			if err != nil {
				t.Fatal(err)
			}
			for _, sent := range recorded.Exchanges {
				if sent.Status != http.StatusOK {
					continue
				}
				if _, err := elsewhere.Verify(recorded.reply(t, sent.Name)); err == nil {
					t.Fatalf("%s verifies under a key the platform's operator never held", sent.Name)
				}
			}
		})
	}
}

func policyRecordings(t *testing.T) []policyRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("no platform was recorded handing an agent its policy")
	}
	found := make([]policyRecording, 0, len(manifests))
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := policyRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		if recorded.Platform.Commit == "" || recorded.Platform.Contracts == "" || recorded.RecordedAt.IsZero() || recorded.Signers == "" {
			t.Fatalf("%s does not say which platform, contracts, moment and signer it was recorded with", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func (r policyRecording) name() string { return filepath.Base(r.directory) }

func (r policyRecording) reply(t *testing.T, name string) []byte {
	t.Helper()
	held, err := os.ReadFile(filepath.Join(r.directory, name+".reply.pb"))
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func (r policyRecording) verifier(t *testing.T) *policy.Verifier {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(r.directory, r.Signers))
	if err != nil {
		t.Fatal(err)
	}
	var keys []*ecdsa.PublicKey
	for rest := content; ; {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := parsed.(*ecdsa.PublicKey)
		keys = append(keys, key)
		rest = remainder
	}
	verifier, err := policy.NewVerifier(keys)
	if err != nil {
		t.Fatalf("read the signers %s recorded: %v", r.name(), err)
	}
	return verifier
}

func ownConfiguration(t *testing.T) config.Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Seagull platform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, authority, authority, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(directory, "platform-ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent.json")
	content := fmt.Sprintf(`{"format": 1, "identity": {"state_directory": %q},
		"server": {"ingest_url": "https://gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q},
		"modules": {"authentication": {"enabled": true}}}`, filepath.Join(directory, "state"), bundle)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return settings
}
