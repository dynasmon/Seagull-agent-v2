//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	signersPath       = "/etc/seagull-agent/policy-signers.pem"
	policyPayloadType = "application/vnd.seagull.policy.v1+protobuf"
)

// The policy the platform hands the agent that asks, as the recorded platform
// answers: the envelope it holds, a 304 to an agent naming it, and no_policy
// while it holds none.
func (p *platform) policy(w http.ResponseWriter, r *http.Request) {
	held := p.handed.Load()
	if held == nil {
		encoded, _ := proto.Marshal(&controlv1.Refusal{Code: "no_policy", Detail: "no policy names this agent"})
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusNotFound)
		w.Write(encoded)
		return
	}
	sum := sha256.Sum256(*held)
	tag := strconv.Quote(hex.EncodeToString(sum[:]))
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(*held)
}

func sealPolicy(t *testing.T, revision uint64, settings *policyv1.Settings, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&policyv1.Policy{
		SchemaVersion: 1,
		PolicyId:      "gate-servers",
		Revision:      revision,
		Targets:       &policyv1.Targets{AgentIds: []string{agentID}},
		IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(now.Add(24 * time.Hour)),
		Settings:      settings,
	})
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	authenticated := fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(policyPayloadType), policyPayloadType, len(payload))
	digest := sha256.Sum256(append(authenticated, payload...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign the policy: %v", err)
	}
	envelope, err := proto.Marshal(&policyv1.SignedPolicy{
		Payload:     payload,
		PayloadType: policyPayloadType,
		Signatures:  []*policyv1.Signature{{Sig: signature}},
	})
	if err != nil {
		t.Fatalf("encode the envelope: %v", err)
	}
	return envelope
}

// An operator signs a policy off the platform and hands the service the public
// half of the key; the agent applies what the platform hands it within the
// ceilings of its configuration, keeps it across a restart under the installed
// permissions, and refuses a policy nobody it trusts signed.
func (g *gate) policies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the signing key: %v", err)
	}
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw another key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the signer: %v", err)
	}
	place(t, signersPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	first := sealPolicy(t, 1, &policyv1.Settings{
		LogLevel: policyv1.LogLevel_LOG_LEVEL_DEBUG,
		Budgets:  &policyv1.Budgets{MemoryLimitBytes: 128 << 20, MaxConcurrentUploads: 8},
	}, key)
	g.platform.handed.Store(&first)
	g.signers = signersPath
	g.write(t)
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)

	applied := await(t, g.invocation, "policy_applied", 20*time.Second)
	if applied["how"] != "handed" || applied["revision"] != float64(1) || applied["policy_id"] != "gate-servers" || applied["kept_resources_max_concurrent_uploads"] != "1" {
		t.Fatalf("the agent applied %v", applied)
	}
	var spending map[string]any
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "agent_resources" {
			spending, _ = entry["budgets"].(map[string]any)
		}
	}
	if spending["memory_limit"] != float64(128<<20) || spending["max_concurrent_uploads"] != float64(1) {
		t.Errorf("under the policy the agent spends %v", spending)
	}
	owns(t, filepath.Join(state, "policy"), g.uid, g.gid, fs.ModeDir|0o700)
	owns(t, filepath.Join(state, "policy", "policy.json"), g.uid, g.gid, 0o600)
	g.statusSays(t, true, "\npolicy: running since ", "revision 1 of gate-servers")

	second := sealPolicy(t, 2, &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN}, stranger)
	g.platform.handed.Store(&second)
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)
	if held := await(t, g.invocation, "policy_applied", 20*time.Second); held["how"] != "held" || held["revision"] != float64(1) {
		t.Errorf("after a restart the agent held %v", held)
	}
	refused := await(t, g.invocation, "policy_refused", 20*time.Second)
	if cause := fmt.Sprint(refused["error"]); !strings.Contains(cause, "no signature") || refused["recovery"] == nil {
		t.Errorf("the agent refused a policy nobody it trusts signed with %v", refused)
	}
	g.statusSays(t, false, "\npolicy: degraded since ", "refused the policy it was handed last")

	run(t, "systemctl", "stop", unit)
	g.signers = ""
	g.platform.handed.Store(nil)
	g.write(t)
}
