package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

// The listener the agent renews on, as far as policies go: it hands the agent
// whatever envelope it holds, answers that nothing changed when the agent names
// that envelope, and says no policy names the agent while it holds none.
type handing struct {
	*served
	mu       sync.Mutex
	envelope []byte
	asked    []string
}

func handingPolicies(t *testing.T, signing *issuing) *handing {
	t.Helper()
	held := &handing{served: &served{}}
	signing.serving(t, held.served, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		held.mu.Lock()
		defer held.mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != policy.Path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		held.asked = append(held.asked, r.Header.Get("If-None-Match"))
		if held.envelope == nil {
			body, _ := proto.Marshal(&controlv1.Refusal{Code: "no_policy", Detail: "no policy names this agent"})
			w.WriteHeader(http.StatusNotFound)
			w.Write(body)
			return
		}
		sum := sha256.Sum256(held.envelope)
		tag := strconv.Quote(hex.EncodeToString(sum[:]))
		w.Header().Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(held.envelope)
	}))
	return held
}

func (h *handing) hand(envelope []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.envelope, h.asked = envelope, nil
}

func (h *handing) wasAsked(t *testing.T) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		asked := slices.Clone(h.asked)
		h.mu.Unlock()
		if len(asked) > 0 {
			return asked
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the agent never asked for its policy")
	return nil
}

func policyKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a policy signing key: %v", err)
	}
	return key
}

func signersFile(t *testing.T, path string, keys ...*ecdsa.PrivateKey) string {
	t.Helper()
	var encoded []byte
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("encode a signer: %v", err)
		}
		encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	}
	signers := filepath.Join(filepath.Dir(path), "policy-signers.pem")
	if err := os.WriteFile(signers, encoded, 0o644); err != nil {
		t.Fatalf("write the signers: %v", err)
	}
	return signers
}

func revision(number uint64, settings *policyv1.Settings, agents ...string) *policyv1.Policy {
	now := time.Now().UTC()
	return &policyv1.Policy{
		SchemaVersion: policy.SchemaVersion,
		PolicyId:      "linux-web",
		Revision:      number,
		Targets:       &policyv1.Targets{AgentIds: agents},
		IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(now.Add(30 * 24 * time.Hour)),
		Settings:      settings,
	}
}

func sealedPolicy(t *testing.T, held *policyv1.Policy, keys ...*ecdsa.PrivateKey) []byte {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(held)
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	digest := sha256.Sum256(policy.PAE(policy.PayloadType, payload))
	envelope := &policyv1.SignedPolicy{Payload: payload, PayloadType: policy.PayloadType}
	for _, key := range keys {
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("sign the policy: %v", err)
		}
		envelope.Signatures = append(envelope.Signatures, &policyv1.Signature{Sig: signature})
	}
	served, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode the envelope: %v", err)
	}
	return served
}

func policied(t *testing.T) (path, state string, platform *handing, key *ecdsa.PrivateKey) {
	t.Helper()
	state = stateDirectory(t)
	path = configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	enrollWith(t, path, signing)
	platform = handingPolicies(t, signing)
	key = policyKey(t)
	rewrite(t, path, state, map[string]string{
		"server": servers("https://gateway.example:8443", platform.URL, trustBundle(path)),
		"policy": fmt.Sprintf(`{"signers": %q, "interval": "1h"}`, signersFile(t, path, key)),
	})
	return path, state, platform, key
}

func awaitRun(t *testing.T, path string, messages ...string) []map[string]any {
	t.Helper()
	entries, stop := running(t, path)
	found := make([]map[string]any, 0, len(messages))
	for _, message := range messages {
		found = append(found, await(t, entries, message))
	}
	if code, rest := stop(); code != 0 {
		t.Fatalf("the agent exited with %d, last saying %v", code, rest)
	}
	return found
}

func TestAnEnrolledAgentRunsOnThePolicySignedForItAndOnlyGoesForward(t *testing.T) {
	path, state, platform, key := policied(t)
	quieter := &policyv1.Settings{
		LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN,
		Budgets:  &policyv1.Budgets{SpoolMaxBytes: 256 << 20, MaxConcurrentUploads: 4},
	}
	second := sealedPolicy(t, revision(2, quieter, "web-01", "web-02"), key)

	platform.hand(second)
	applied := awaitRun(t, path, "policy_applied")[0]
	if applied["how"] != "handed" || applied["revision"] != float64(2) || applied["policy_id"] != "linux-web" ||
		applied["kept_resources_max_concurrent_uploads"] != "1" {
		t.Fatalf("the agent applied %v", applied)
	}
	described, err := status.Read(filepath.Join(state, statusDirectory))
	if err != nil {
		t.Fatalf("read the status: %v", err)
	}
	component := slices.IndexFunc(described.Components, func(held status.Component) bool { return held.Name == "policy" })
	if component < 0 || described.Components[component].State != status.Running ||
		!strings.Contains(string(described.Components[component].Reason), "revision 2 of linux-web") {
		t.Fatalf("the status says of the policy %+v", described.Components)
	}

	platform.hand(second)
	entries, stop := running(t, path)
	held := await(t, entries, "policy_applied")
	asked := platform.wasAsked(t)
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
	sum := sha256.Sum256(second)
	if held["how"] != "held" || held["revision"] != float64(2) || asked[0] != strconv.Quote(hex.EncodeToString(sum[:])) {
		t.Fatalf("after a restart the agent held %v and asked naming %v", held, asked)
	}
	if running := loaded(t, path); running.Logging.Level != "info" {
		t.Fatalf("the policy changed the configuration file: %+v", running.Logging)
	}

	stranger := policyKey(t)
	var changed policyv1.SignedPolicy
	if err := proto.Unmarshal(sealedPolicy(t, revision(3, quieter, "web-01"), key), &changed); err != nil {
		t.Fatal(err)
	}
	changed.Payload[len(changed.Payload)-1] ^= 0x01
	tampered, err := proto.Marshal(&changed)
	if err != nil {
		t.Fatal(err)
	}
	expired := revision(3, quieter, "web-01")
	expired.IssuedAt, expired.ExpiresAt = timestamppb.New(time.Now().Add(-48*time.Hour)), timestamppb.New(time.Now().Add(-time.Hour))
	for name, refused := range map[string]struct {
		envelope []byte
		says     string
	}{
		"an older revision":                         {envelope: sealedPolicy(t, revision(1, quieter, "web-01"), key), says: "older than the one the agent applied"},
		"a policy changed after it was signed":      {envelope: tampered, says: "no signature"},
		"a policy signed by a key it was not given": {envelope: sealedPolicy(t, revision(3, quieter, "web-01"), stranger), says: "no signature"},
		"a policy that expired":                     {envelope: sealedPolicy(t, expired, key), says: "expired"},
		"a policy for other agents":                 {envelope: sealedPolicy(t, revision(3, quieter, "web-02"), key), says: "does not name this agent"},
		"a policy it would not run on": {envelope: sealedPolicy(t, revision(3, &policyv1.Settings{
			Budgets: &policyv1.Budgets{MemoryLimitBytes: 1 << 20},
		}, "web-01"), key), says: "resources.memory_limit"},
	} {
		t.Run(name, func(t *testing.T) {
			platform.hand(refused.envelope)
			found := awaitRun(t, path, "policy_applied", "policy_refused")
			if found[0]["revision"] != float64(2) {
				t.Fatalf("the agent started on %v", found[0])
			}
			if cause, _ := found[1]["error"].(string); !strings.Contains(cause, refused.says) || found[1]["recovery"] == "" {
				t.Fatalf("the agent refused %s with %v", name, found[1])
			}
		})
	}

	platform.hand(sealedPolicy(t, revision(3, &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_DEBUG}, "web-01"), key))
	if newer := awaitRun(t, path, "policy_applied", "policy_applied")[1]; newer["how"] != "handed" || newer["revision"] != float64(3) {
		t.Fatalf("the agent applied %v", newer)
	}

	signersFile(t, path, stranger)
	if withdrawn := awaitRun(t, path, "policy_not_applied")[0]; withdrawn["revision"] != float64(3) ||
		!strings.Contains(fmt.Sprint(withdrawn["error"]), "no signature") {
		t.Fatalf("an agent no longer accepting the key that signed its policy logged %v", withdrawn)
	}
}

func TestReadingTheConfigurationAgainVerifiesThePolicyAgainUnderTheKeysItNamesNow(t *testing.T) {
	path, state, platform, key := policied(t)
	platform.hand(sealedPolicy(t, revision(4, &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN}, "web-01"), key))
	awaitRun(t, path, "policy_applied")

	installation, err := identity.Open(state)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	defer installation.Close()
	local := loaded(t, path)
	var logs bytes.Buffer
	held := configuration{
		logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		path:   path,
		active: config.Activate(local),
		local:  local,
		level:  new(slog.LevelVar),
	}
	if err := held.hold(installation, "web-01", time.Now()); err != nil {
		t.Fatalf("hold the policy: %v", err)
	}
	if running := held.active.Settings(); running.Logging.Level != "warn" {
		t.Fatalf("the held policy left the agent logging at %s", running.Logging.Level)
	}

	signersFile(t, path, policyKey(t))
	reload(t, &held)
	if _, found := logged(t, logs.String(), "policy_withdrawn"); !found || held.active.Settings().Logging.Level != "info" {
		t.Fatalf("a policy no accepted key signed stayed in force:\n%s", logs.String())
	}
	if component := held.policied(nil, time.Now()); component.State != status.Degraded || !strings.Contains(string(component.Reason), "not in force") {
		t.Fatalf("the status says of a withdrawn policy %+v", component)
	}

	signersFile(t, path, key)
	logs.Reset()
	reload(t, &held)
	if again, found := logged(t, logs.String(), "policy_applied"); !found || again["how"] != "verified again" || held.active.Settings().Logging.Level != "warn" {
		t.Fatalf("a policy its key verifies again was not put back in force:\n%s", logs.String())
	}

	rewrite(t, path, state, map[string]string{
		"server":  servers("https://gateway.example:8443", platform.URL, trustBundle(path)),
		"policy":  fmt.Sprintf(`{"signers": %q}`, filepath.Join(filepath.Dir(path), "policy-signers.pem")),
		"modules": `{"inventory": {"enabled": true}}`,
	})
	logs.Reset()
	reload(t, &held)
	if _, found := logged(t, logs.String(), "configuration_reloaded"); !found || !held.active.Settings().Modules["inventory"].Enabled ||
		held.active.Settings().Logging.Level != "warn" {
		t.Fatalf("a reload the policy fits over left %+v:\n%s", held.active.Settings().Modules, logs.String())
	}
}

func TestAPolicyThatExpiresWhileInForceIsKeptAndSaidToHaveExpired(t *testing.T) {
	path, state, platform, key := policied(t)
	brief := revision(5, &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN}, "web-01")
	ending := time.Now().Add(1500 * time.Millisecond)
	brief.ExpiresAt = timestamppb.New(ending)
	platform.hand(sealedPolicy(t, brief, key))
	awaitRun(t, path, "policy_applied")
	time.Sleep(time.Until(ending) + 100*time.Millisecond)

	entries, stop := running(t, path)
	held := await(t, entries, "policy_applied")
	expired := await(t, entries, "policy_expired")
	code, rest := stop()
	if code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
	if held["how"] != "held" || expired["revision"] != float64(5) || expired["recovery"] == "" {
		t.Fatalf("an agent whose policy expired held %v and said %v", held, expired)
	}
	for _, entry := range rest {
		if entry["msg"] == "policy_expired" {
			t.Fatalf("the agent said its policy expired more than once: %v", entry)
		}
	}
	described, err := status.Read(filepath.Join(state, statusDirectory))
	if err != nil {
		t.Fatalf("read the status: %v", err)
	}
	component := slices.IndexFunc(described.Components, func(held status.Component) bool { return held.Name == "policy" })
	if component < 0 || described.Components[component].State != status.Degraded ||
		!strings.Contains(string(described.Components[component].Reason), "expired") {
		t.Fatalf("the status says of an expired policy %+v", described.Components)
	}
}
