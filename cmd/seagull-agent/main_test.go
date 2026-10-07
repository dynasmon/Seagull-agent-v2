package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/ceilings"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/privileges"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const childArguments = "SEAGULL_AGENT_TEST_ARGUMENTS"

func TestMain(m *testing.M) {
	noted = func(journal.Note) error { return nil }
	if arguments, ok := os.LookupEnv(childArguments); ok {
		os.Exit(run(strings.Fields(arguments), os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func TestTheVersionFlagPrintsTheBuildIdentityApartFromTheWireVersions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	identity, spoken, _ := strings.Cut(stdout.String(), "\n")
	fields := strings.Fields(identity)
	if len(fields) != 4 || fields[0] != "seagull-agent" || fields[2] != runtime.Version() {
		t.Fatalf("build identity %q", identity)
	}
	if platform := runtime.GOOS + "/" + runtime.GOARCH; fields[3] != platform {
		t.Fatalf("build identity names %s, the binary runs on %s", fields[3], platform)
	}
	want := fmt.Sprintf("protocol_version %d\nevent_schema_version %d\ninventory_schema_version %d\n",
		protocol.Version, protocol.EventSchemaVersion, protocol.InventorySchemaVersion)
	if spoken != want {
		t.Fatalf("printed the wire versions as %q, want %q", spoken, want)
	}
}

func TestTheAgentLogsWhatItIsAsItStarts(t *testing.T) {
	path := configured(t, stateDirectory(t), nil)
	logs := serveStopped(t, path)
	created, _ := logged(t, logs, "installation_created")
	started, found := logged(t, logs, "agent_starting")
	if !found || created["installation_id"] == nil {
		t.Fatalf("logged no installation_created and agent_starting:\n%s", logs)
	}
	want := map[string]any{
		"build":                    buildIdentity(),
		"config":                   path,
		"protocol_version":         float64(protocol.Version),
		"event_schema_version":     float64(protocol.EventSchemaVersion),
		"inventory_schema_version": float64(protocol.InventorySchemaVersion),
		"installation_id":          created["installation_id"],
		"key_provider":             "filesystem",
		"key_exportable":           true,
	}
	for name, value := range want {
		if started[name] != value {
			t.Errorf("agent_starting carries %s=%v, want %v: %v", name, started[name], value, started)
		}
	}
	if agentID, enrolled := started["agent_id"]; enrolled {
		t.Errorf("a new installation started as agent %v", agentID)
	}
}

func TestTheAgentReadsBackItsSpoolAsItStarts(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, map[string]string{"spool": `{"max_bytes": "32MiB"}`})
	first, _ := logged(t, serveStopped(t, path), "spool_opened")
	if first["max_bytes"] != float64(32<<20) || first["level"] != "INFO" {
		t.Fatalf("a new installation opened its spool as %v", first)
	}
	held, release := spoolIn(t, state)
	if _, err := held.Admit(spool.Events, spool.Record{ID: "event-1", Payload: []byte("admitted")}, spool.Record{ID: "event-2", Payload: []byte("admitted")}); err != nil {
		t.Fatalf("admit two events: %v", err)
	}
	if err := held.Acknowledge(spool.Events, 1); err != nil {
		t.Fatalf("acknowledge the first event: %v", err)
	}
	release()

	opened, found := logged(t, serveStopped(t, path), "spool_opened")
	events, _ := opened["events"].(map[string]any)
	inventory, _ := opened["inventory"].(map[string]any)
	if !found || events["outstanding"] != float64(1) || events["delivered"] != float64(1) || events["lost"] != float64(0) ||
		events["expired"] != float64(0) || events["quarantined"] != float64(0) || events["max_age"] != float64(72*time.Hour) {
		t.Fatalf("the agent reported its spool as %v", opened)
	}
	if inventory["outstanding"] != float64(0) || opened["bytes"].(float64) <= 0 {
		t.Fatalf("the agent reported its spool as %v", opened)
	}
}

func TestReplacingTheInstallationSetsItsSpoolAside(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	serveStopped(t, path)
	held, release := spoolIn(t, state)
	if _, err := held.Admit(spool.Events, spool.Record{ID: "event-1", Payload: []byte("admitted by the replaced installation")}); err != nil {
		t.Fatalf("admit an event: %v", err)
	}
	release()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "installation", "replace"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	opened, _ := logged(t, serveStopped(t, path), "spool_opened")
	if events, _ := opened["events"].(map[string]any); events["outstanding"] != float64(0) {
		t.Fatalf("the replacement installation holds the records of the one it replaced: %v", opened)
	}
	kept, err := filepath.Glob(filepath.Join(state, "replaced", "*", spoolDirectory, "events", "*.seg"))
	if err != nil || len(kept) != 1 {
		t.Fatalf("the replaced installation's records were not set aside with it: %q %v", kept, err)
	}
}

func TestTheAgentKeepsItsInstallationAcrossRestarts(t *testing.T) {
	path := configured(t, stateDirectory(t), nil)
	first, second := serveStopped(t, path), serveStopped(t, path)
	created, _ := logged(t, first, "installation_created")
	if _, recreated := logged(t, second, "installation_created"); recreated || created["installation_id"] == nil {
		t.Fatalf("the first start created %v and the second created one too: %t", created["installation_id"], recreated)
	}
	for _, logs := range []string{first, second} {
		if started, _ := logged(t, logs, "agent_starting"); started["installation_id"] != created["installation_id"] {
			t.Fatalf("started as installation %v, created %v", started["installation_id"], created["installation_id"])
		}
	}
}

func TestAnInstallationIsEnrolledWithTheCertificateThePlatformIssuedForItsRequest(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	gateway := signing.listen(t)

	var asked, told bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "request", "web-01"}, &asked, &told); code != 0 {
		t.Fatalf("exit code %d: %s", code, told.String())
	}
	block, rest := pem.Decode(asked.Bytes())
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) > 0 {
		t.Fatalf("the agent printed %q rather than a certificate request", asked.String())
	}
	requested, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || requested.CheckSignature() != nil || requested.Subject.CommonName != "web-01" {
		t.Fatalf("the agent asked with %v: %v", requested, err)
	}
	keys, err := filepath.Glob(filepath.Join(state, keysDirectory, "*.pem"))
	digest := sha256.Sum256(requested.RawSubjectPublicKeyInfo)
	if err != nil || len(keys) != 1 || filepath.Base(keys[0]) != hex.EncodeToString(digest[:])+".pem" {
		t.Fatalf("the installation holds %q and asked with key %x: %v", keys, digest, err)
	}
	for _, said := range []string{"asks to be agent web-01 with key " + hex.EncodeToString(digest[:]), "POST /v1/agents/web-01/certificate", "enrollment import ISSUED"} {
		if !strings.Contains(told.String(), said) {
			t.Errorf("the agent did not say %q:\n%s", said, told.String())
		}
	}

	answer := saved(t, signing.issue(t, asked.Bytes(), nil))
	var imported, importing bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "import", answer}, &imported, &importing); code != 0 || importing.Len() != 0 {
		t.Fatalf("exit code %d, stdout %q, stderr %q", code, imported.String(), importing.String())
	}
	if said := imported.String(); !strings.Contains(said, "is enrolled as agent web-01: credential generation 1, certificate ") ||
		!strings.Contains(said, `issued by "Seagull platform"`) {
		t.Fatalf("the agent reported the import as %q", said)
	}
	var again bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "import", answer}, &again, &importing); code != 0 || !strings.Contains(again.String(), "web-01, already: credential generation 1") {
		t.Fatalf("importing again exited %d and said %q", code, again.String())
	}

	logs := serveStopped(t, path)
	started, _ := logged(t, logs, "agent_starting")
	if started["agent_id"] != "web-01" || started["credential_generation"] != float64(1) {
		t.Fatalf("the enrolled installation started as %v", started)
	}
	for _, written := range []string{asked.String(), told.String(), imported.String(), again.String(), logs} {
		if exposesKeys(t, written, state) {
			t.Fatalf("the agent wrote down its key:\n%s", written)
		}
	}

	installation, err := identity.Open(state)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	defer installation.Close()
	held, err := openKeys(installation, config.KeysInFiles)
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	certificates, err := openCertificates(installation)
	if err != nil {
		t.Fatalf("open the certificates: %v", err)
	}
	settings := loaded(t, path)
	authorities, err := settings.Server.Authorities()
	if err != nil {
		t.Fatalf("read the authorities: %v", err)
	}
	client, err := platform(settings, authorities, &credentials{installation: installation, keys: held, certificates: certificates})
	if err != nil {
		t.Fatalf("compose the transport: %v", err)
	}
	defer client.Close()
	reply, err := client.Post(t.Context(), transport.Request{URL: gateway.URL + "/v1/events", ContentType: "application/x-protobuf"})
	if err != nil || reply.Status != http.StatusOK {
		t.Fatalf("the enrolled agent reached the platform with %v: %v", reply.Status, err)
	}
	if agent := gateway.agent.Load(); agent == nil || *agent != "web-01" {
		t.Fatalf("the platform authenticated the agent as %v", agent)
	}
}

func TestAskingAgainForTheSameAgentPrintsTheSameRequest(t *testing.T) {
	path := configured(t, stateDirectory(t), nil)
	keysAsked := map[string]bool{}
	for attempt := range 2 {
		var asked, told bytes.Buffer
		if code := run([]string{"-config", path, "enrollment", "request", "web-01"}, &asked, &told); code != 0 {
			t.Fatalf("exit code %d: %s", code, told.String())
		}
		block, _ := pem.Decode(asked.Bytes())
		if block == nil {
			t.Fatalf("the agent printed %q", asked.String())
		}
		requested, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse the request: %v", err)
		}
		keysAsked[string(requested.RawSubjectPublicKeyInfo)] = true
		if again := strings.Contains(told.String(), "asks again to be agent web-01"); again != (attempt == 1) {
			t.Fatalf("request %d said %q", attempt+1, told.String())
		}
	}
	if len(keysAsked) != 1 {
		t.Fatalf("asking twice asked with %d keys", len(keysAsked))
	}
}

func TestAnImportTheAgentRefusesChangesNothing(t *testing.T) {
	marker := strings.Repeat("written", 36) + "-marker-tail"
	now := time.Now()
	cases := []struct {
		name     string
		answer   func(t *testing.T, signing *issuing, requested []byte) string
		cause    string
		recovery string
	}{
		{
			name: "a certificate an impostor issued",
			answer: func(t *testing.T, _ *issuing, requested []byte) string {
				impostor := listening(t, filepath.Join(t.TempDir(), "impostor-ca.pem"))
				return saved(t, impostor.issue(t, requested, nil))
			},
			cause:    enrollment.ErrUntrusted.Error(),
			recovery: "server.trust_bundle",
		},
		{
			name: "a certificate for another agent",
			answer: func(t *testing.T, signing *issuing, requested []byte) string {
				return saved(t, signing.issue(t, requested, func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: marker} }))
			},
			cause:    enrollment.ErrMismatched.Error(),
			recovery: "enrollment request AGENT_ID",
		},
		{
			name: "a certificate that expired",
			answer: func(t *testing.T, signing *issuing, requested []byte) string {
				return saved(t, signing.issue(t, requested, func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour) }))
			},
			cause:    enrollment.ErrNotCurrent.Error(),
			recovery: "clock",
		},
		{
			name: "the certificate alone",
			answer: func(t *testing.T, signing *issuing, requested []byte) string {
				var issued agentv1.IssuedCertificate
				if err := proto.Unmarshal(signing.issue(t, requested, nil), &issued); err != nil {
					t.Fatalf("decode the answer: %v", err)
				}
				return saved(t, issued.GetCertificatePem())
			},
			cause:    enrollment.ErrUnreadable.Error(),
			recovery: "seagull.agent.v1.IssuedCertificate",
		},
		{
			name: "a file that is not there",
			answer: func(t *testing.T, _ *issuing, _ []byte) string {
				return filepath.Join(t.TempDir(), marker)
			},
			cause:    enrollment.ErrUnreadable.Error(),
			recovery: "as it answered",
		},
		{
			name: "a directory",
			answer: func(t *testing.T, _ *issuing, _ []byte) string {
				return t.TempDir()
			},
			cause:    enrollment.ErrUnreadable.Error(),
			recovery: "as it answered",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := stateDirectory(t)
			path := configured(t, state, nil)
			signing := listening(t, trustBundle(path))
			var asked, told bytes.Buffer
			if code := run([]string{"-config", path, "enrollment", "request", "web-01"}, &asked, &told); code != 0 {
				t.Fatalf("exit code %d: %s", code, told.String())
			}
			before, err := os.ReadFile(filepath.Join(state, "installation.json"))
			if err != nil {
				t.Fatalf("read the installation state: %v", err)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-config", path, "enrollment", "import", c.answer(t, signing, asked.Bytes())}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
				t.Fatalf("exit code %d, stdout %q", code, stdout.String())
			}
			if said := stderr.String(); !strings.Contains(said, c.cause) || !strings.Contains(said, c.recovery) ||
				strings.Contains(said, "-marker-tail") {
				t.Fatalf("the agent refused the import with\n%s\nwant %q and a recovery naming %q, and nothing of what it read", said, c.cause, c.recovery)
			}
			if after, err := os.ReadFile(filepath.Join(state, "installation.json")); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("a refused import changed the installation state: %v", err)
			}
			if kept, err := os.ReadDir(filepath.Join(state, certificatesDirectory)); (err != nil && !errors.Is(err, fs.ErrNotExist)) || len(kept) != 0 {
				t.Fatalf("a refused import kept %v: %v", kept, err)
			}
		})
	}
}

func TestNothingIsImportedOrAskedForBeyondWhatTheInstallationMayBecome(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	unasked := saved(t, signing.issue(t, requestFor(t, "web-01"), nil))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "import", unasked}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), enrollment.ErrNotAsked.Error()) || !strings.Contains(stderr.String(), "enrollment request AGENT_ID") {
		t.Fatalf("importing without a request exited %d and said %q", code, stderr.String())
	}

	enrollWith(t, path, signing)
	for _, agentID := range []string{"db-07", "web 01"} {
		stdout.Reset()
		stderr.Reset()
		if code := run([]string{"-config", path, "enrollment", "request", agentID}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Fatalf("asking to be %q exited %d and printed %q", agentID, code, stdout.String())
		}
		if !strings.Contains(stderr.String(), identity.ErrUnasked.Error()) || !strings.Contains(stderr.String(), "installation replace") {
			t.Fatalf("asking to be %q was refused with %q", agentID, stderr.String())
		}
	}
	if keys, err := filepath.Glob(filepath.Join(state, keysDirectory, "*.pem")); err != nil || len(keys) != 1 {
		t.Fatalf("refused requests left %q: %v", keys, err)
	}
}

func TestAnEnrolledInstallationMovesToTheCertificateItAsksForNext(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	first := enrollWith(t, path, signing)
	second := enrollWith(t, path, signing)
	if second.key == first.key || second.certificate == first.certificate {
		t.Fatalf("the next generation holds %s and %s, the first %s and %s", second.key, second.certificate, first.key, first.certificate)
	}
	started, _ := logged(t, serveStopped(t, path), "agent_starting")
	if started["agent_id"] != "web-01" || started["credential_generation"] != float64(2) {
		t.Fatalf("the installation started as %v", started)
	}
	if _, err := os.Lstat(first.key); err != nil {
		t.Fatalf("the key of the first generation is gone: %v", err)
	}
}

func TestEnrollingWaitsForTheAgentToStop(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	held, err := identity.Open(state)
	if err != nil {
		t.Fatalf("hold the installation: %v", err)
	}
	defer held.Close()
	answer := saved(t, signing.issue(t, requestFor(t, "web-01"), nil))
	for _, command := range [][]string{{"enrollment", "request", "web-01"}, {"enrollment", "import", answer}} {
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"-config", path}, command...), &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "another agent process holds the installation state") ||
			!strings.Contains(stderr.String(), "stop the agent that holds "+state) {
			t.Fatalf("%q exited %d while the agent ran and said %q", command, code, stderr.String())
		}
	}
}

func TestAnImportSaysWhichAuthoritiesThePlatformTrustsThatTheAgentDoesNot(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	next := listening(t, filepath.Join(t.TempDir(), "next-ca.pem"))
	next.certificate.Subject.CommonName = "Seagull platform next"
	signing.published = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: next.certificate.Raw})

	var asked, told bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "request", "web-01"}, &asked, &told); code != 0 {
		t.Fatalf("exit code %d: %s", code, told.String())
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "import", saved(t, signing.issue(t, asked.Bytes(), nil))}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	if said := stderr.String(); !strings.Contains(said, "trust \"Seagull platform\", which the agent does not: add it to") ||
		!strings.Contains(said, trustBundle(path)) || strings.Count(said, "\n") != 1 {
		t.Fatalf("the agent said %q about the authorities the platform publishes", said)
	}
}

func requestFor(t *testing.T, agentID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key the installation does not hold: %v", err)
	}
	signed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		t.Fatalf("make a request: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signed})
}

func TestAnEnrolledAgentRenewsItsCredentialAsItRuns(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	renewing := signing.renewing(t, "", 0)
	rewrite(t, path, state, map[string]string{"server": servers("https://gateway.example:8443", renewing.URL, trustBundle(path))})
	var asked, told bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "request", "web-01"}, &asked, &told); code != 0 {
		t.Fatalf("ask for a certificate: exit code %d: %s", code, told.String())
	}
	now := time.Now().UTC().Truncate(time.Second)
	short := saved(t, signing.issue(t, asked.Bytes(), func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now, now.Add(3*time.Second) }))
	if code := run([]string{"-config", path, "enrollment", "import", short}, &asked, &told); code != 0 {
		t.Fatalf("import a certificate valid for seconds: exit code %d: %s", code, told.String())
	}

	entries, stop := running(t, path)
	scheduled := await(t, entries, "credential_renewal_scheduled")
	renewed := await(t, entries, "credential_renewed")
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
	if scheduled["agent_id"] != "web-01" || renewed["credential_generation"] != float64(2) || renewed["key"] != "kept" || renewing.served.Load() != 1 {
		t.Fatalf("the agent scheduled %v and renewed %v after %d requests", scheduled, renewed, renewing.served.Load())
	}
	started, _ := logged(t, serveStopped(t, path), "agent_starting")
	if started["credential_generation"] != float64(2) {
		t.Fatalf("after renewing, the agent started as %v", started)
	}
}

func TestAnAgentThatIsNotEnrolledHasNothingToRenew(t *testing.T) {
	entries, stop := running(t, configured(t, stateDirectory(t), nil))
	components := []any{await(t, entries, "component_started")["component"]}
	code, rest := stop()
	for _, entry := range rest {
		if entry["msg"] == "component_started" {
			components = append(components, entry["component"])
		}
	}
	if code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
	if !slices.Equal(components, []any{"configuration", "collection", "status"}) {
		t.Fatalf("an agent that is not enrolled ran %v", components)
	}
}

func TestAnEnrolledAgentDeliversWhatItsSpoolHoldsAsItRuns(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	var mu sync.Mutex
	var received, agents []string
	ingest := signing.serving(t, &served{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var batch ingestv1.EventBatch
		if err != nil || r.URL.Path != "/v1/events" || proto.Unmarshal(body, &batch) != nil {
			http.Error(w, "not a batch of events", http.StatusBadRequest)
			return
		}
		mu.Lock()
		for _, event := range batch.GetEvents() {
			received = append(received, event.GetEventId())
		}
		agents = append(agents, r.TLS.PeerCertificates[0].Subject.CommonName)
		mu.Unlock()
		acknowledged, _ := proto.Marshal(&ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(batch.GetEvents()))})
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(acknowledged)
	}))
	rewrite(t, path, state, map[string]string{"server": servers(ingest.URL, signing.listen(t).URL, trustBundle(path))})
	enrollWith(t, path, signing)
	held, release := spoolIn(t, state)
	var ids []string
	for i := range 3 {
		id := fmt.Sprintf("event-%d", i)
		payload, err := proto.Marshal(&eventv1.Event{EventId: id, SchemaVersion: protocol.EventSchemaVersion})
		if err == nil {
			_, err = held.Admit(spool.Events, spool.Record{ID: id, Payload: payload})
		}
		if err != nil {
			t.Fatalf("admit %s: %v", id, err)
		}
		ids = append(ids, id)
	}
	release()

	entries, stop := running(t, path)
	var components []any
	deadline := time.After(10 * time.Second)
	for delivered := false; !delivered; {
		select {
		case entry := <-entries:
			if entry["msg"] == "component_started" {
				components = append(components, entry["component"], entry["policy"])
			}
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatalf("the platform received %v within 10s", received)
		}
		mu.Lock()
		delivered = len(received) == len(ids)
		mu.Unlock()
	}
	code, rest := stop()
	for _, entry := range rest {
		if entry["msg"] == "component_started" {
			components = append(components, entry["component"], entry["policy"])
		}
	}
	if code != 0 || !slices.Equal(components, []any{"configuration", "essential", "collection", "optional", "renewal", "optional", "delivery", "essential", "status", "optional"}) {
		t.Fatalf("the agent exited with %d after running %v", code, components)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(received, ids) || slices.ContainsFunc(agents, func(agent string) bool { return agent != "web-01" }) {
		t.Fatalf("the platform received %v from %v", received, agents)
	}
	opened, _ := logged(t, serveStopped(t, path), "spool_opened")
	if events, _ := opened["events"].(map[string]any); events["outstanding"] != float64(0) || events["delivered"] != float64(3) {
		t.Fatalf("after delivering, the agent opened its spool as %v", opened)
	}
}

func TestADeliveryThePlatformHoldsBackSaysWhatToDo(t *testing.T) {
	path, state := "/etc/seagull-agent/agent.json", "/var/lib/seagull-agent"
	for _, c := range []struct {
		err  error
		says string
	}{
		{err: &protocol.Exclusion{Reason: protocol.Unidentified}, says: "reads no agent in the certificate this installation presents"},
		{err: &protocol.Exclusion{Reason: protocol.Unregistered}, says: "registers the agent this installation was enrolled as"},
		{err: &protocol.Exclusion{Reason: protocol.Unadmitted}, says: `replaces the installation with "seagull-agent -config /etc/seagull-agent/agent.json installation replace"`},
		{err: &protocol.Incompatibility{Field: "event_class", Value: "EVENT_CLASS_AUTHENTICATION", Record: 0}, says: "run an agent release the platform takes"},
		{err: &protocol.Dispute{Field: "time.event_time"}, says: "check the clock of this host against the platform's"},
		{err: &protocol.Refusal{Status: http.StatusNotFound}, says: "server.ingest_url in /etc/seagull-agent/agent.json names the platform's ingest listener"},
		{err: fmt.Errorf("%w: text/html", protocol.ErrNoAcknowledgement), says: "server.ingest_url in /etc/seagull-agent/agent.json"},
		{err: fmt.Errorf("%w: context deadline exceeded", transport.ErrUnanswered), says: "transport.request_timeout in /etc/seagull-agent/agent.json"},
	} {
		if told := recovery(path, state, fmt.Errorf("deliver events: %w", c.err)); !strings.Contains(told, c.says) {
			t.Errorf("%v is recovered from with %q", c.err, told)
		}
	}
}

func TestTheAgentRenewsFromTheCommandLineAndTrustsWhatThePlatformPublished(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	next := listening(t, filepath.Join(t.TempDir(), "next-ca.pem"))
	signing.published = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: next.certificate.Raw})
	ingest, renewing := next.listen(t), signing.renewing(t, "", 0)
	rewrite(t, path, state, map[string]string{"server": servers(ingest.URL, renewing.URL, trustBundle(path))})
	enrollWith(t, path, signing)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "renew"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	said := stdout.String()
	if !strings.Contains(said, "renewed agent web-01 to credential generation 2, with the key it held") ||
		!strings.Contains(said, "against the 2 authorities the platform published from now on") {
		t.Fatalf("the agent reported the renewal as %q", said)
	}
	started, _ := logged(t, serveStopped(t, path), "agent_starting")
	if started["credential_generation"] != float64(2) || started["trust"] != "published" {
		t.Fatalf("after renewing, the agent started as %v", started)
	}

	stdout.Reset()
	if code := run([]string{"-config", path, "platform", "check"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), "checked against the 2 authorities it published to the installation") {
		t.Fatalf("checking the platform against the authorities it published exited %d with %q and %q", code, stdout.String(), stderr.String())
	}

	listening(t, trustBundle(path))
	logs := serveStopped(t, path)
	started, _ = logged(t, logs, "agent_starting")
	if _, reset := logged(t, logs, "authorities_reset"); !reset || started["trust"] != "server.trust_bundle" {
		t.Fatalf("an operator who changed server.trust_bundle left the agent trusting %v", started["trust"])
	}
}

func TestARenewalThePlatformRefusesSaysWhatToDo(t *testing.T) {
	for name, c := range map[string]struct {
		code     string
		status   int
		recovery []string
	}{
		"an agent or a certificate the platform no longer renews": {code: "illegal_move", status: http.StatusUnprocessableEntity, recovery: []string{
			"no longer renews the certificate this installation presents", "when it was revoked or decommissioned",
			"because the answer to a renewal was lost or because another installation holds this installation's key",
			"revokes the agent and replaces the installation", "enrollment request AGENT_ID", "the agent never enrolls itself again",
		}},
		"an agent renewing often": {code: "rate_limited", status: http.StatusTooManyRequests, recovery: []string{"bounds how often an agent renews"}},
	} {
		t.Run(name, func(t *testing.T) {
			state := stateDirectory(t)
			path := configured(t, state, nil)
			signing := listening(t, trustBundle(path))
			renewing := signing.renewing(t, c.code, c.status)
			rewrite(t, path, state, map[string]string{"server": servers("https://gateway.example:8443", renewing.URL, trustBundle(path))})
			enrollWith(t, path, signing)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-config", path, "enrollment", "renew"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
				t.Fatalf("exit code %d, stdout %q", code, stdout.String())
			}
			said := stderr.String()
			if !strings.Contains(said, c.code) {
				t.Fatalf("the refusal was reported as %q", said)
			}
			for _, recovery := range c.recovery {
				if !strings.Contains(said, recovery) {
					t.Errorf("the refusal was reported as %q, which does not say %q", said, recovery)
				}
			}
			started, _ := logged(t, serveStopped(t, path), "agent_starting")
			if started["credential_generation"] != float64(1) {
				t.Fatalf("a refused renewal left the agent at %v", started)
			}
		})
	}
}

func TestRenewingAnInstallationThatIsNotEnrolledIsRefused(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", configured(t, stateDirectory(t), nil), "enrollment", "renew"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), renewal.ErrNotEnrolled.Error()) || !strings.Contains(stderr.String(), "enroll the installation first") {
		t.Fatalf("renewing an installation that is not enrolled exited %d and said %q", code, stderr.String())
	}
}

func TestAnEnrolledAgentStartsWithTheKeyItsCredentialsName(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	enroll(t, path)

	logs := serveStopped(t, path)
	started, _ := logged(t, logs, "agent_starting")
	if started["agent_id"] != "web-01" || started["credential_generation"] != float64(1) || started["key_provider"] != "filesystem" {
		t.Fatalf("an enrolled installation started as %v", started)
	}
	if exposesKeys(t, logs, state) {
		t.Fatalf("the log shows a key:\n%s", logs)
	}
}

func TestAnAgentWhoseCertificateExpiredStillStarts(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	installation, err := identity.Open(state)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	keys, err := openKeys(installation, config.KeysInFiles)
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	certificates, err := openCertificates(installation)
	if err != nil {
		t.Fatalf("open the certificates: %v", err)
	}
	key, err := keys.Create()
	if err != nil {
		t.Fatalf("create a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "web-01"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, signing.certificate, key.Public(), signing.key)
	if err != nil {
		t.Fatalf("issue an expired certificate: %v", err)
	}
	fingerprint, err := certificates.Store([][]byte{signed, signing.certificate.Raw})
	if err != nil {
		t.Fatalf("keep the certificate: %v", err)
	}
	expired, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}
	if err := installation.Activate(identity.Enrollment{AgentID: "web-01", Generation: 1, KeyID: key.ID(), Certificate: identity.Certificate{
		Subject: "web-01", Serial: "07", FingerprintSHA256: fingerprint, NotBefore: expired.NotBefore, NotAfter: expired.NotAfter,
	}}); err != nil {
		t.Fatalf("activate the expired generation: %v", err)
	}
	if err := installation.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	started, _ := logged(t, serveStopped(t, path), "agent_starting")
	if started["agent_id"] != "web-01" || started["credential_generation"] != float64(1) {
		t.Fatalf("an agent whose certificate expired started as %v", started)
	}
	expiry := expired.NotAfter.UTC().Format(time.RFC3339)
	if _, said, _ := asked(t, path); !strings.Contains(said, "credential: failed since "+expiry+": the certificate of credential generation 1 expired at "+expiry) ||
		!strings.Contains(said, "  what to do: have the platform issue the installation a new certificate") {
		t.Fatalf("the status of an agent whose certificate expired says:\n%s", said)
	}
}

func TestKeysSurviveAnActivationInterruptedBeforeItsStateWasWritten(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	active := enroll(t, path).key
	installation, err := identity.Open(state)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	keys, err := openKeys(installation, config.KeysInFiles)
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	next, err := keys.Create()
	if err != nil {
		t.Fatalf("create the key of the next generation: %v", err)
	}
	interrupted := filepath.Join(state, ".installation.json.0123456789abcdef.tmp")
	if err := os.WriteFile(interrupted, []byte(`{"format": 1, "enrollment": {"generation": 2, "key_id": "`+next.ID()), 0o600); err != nil {
		t.Fatalf("interrupt the activation: %v", err)
	}
	if err := installation.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	started, _ := logged(t, serveStopped(t, path), "agent_starting")
	if started["credential_generation"] != float64(1) {
		t.Fatalf("after the interruption the agent started as %v", started)
	}
	installation, err = identity.Open(state)
	if err != nil {
		t.Fatalf("reopen the installation: %v", err)
	}
	defer installation.Close()
	if keys, err = openKeys(installation, config.KeysInFiles); err != nil {
		t.Fatalf("reopen the keys: %v", err)
	}
	enrolled, _ := installation.Enrollment()
	for _, id := range []string{enrolled.KeyID, next.ID()} {
		if _, err := keys.Open(id); err != nil {
			t.Fatalf("key %s did not survive the interrupted activation: %v", id, err)
		}
	}
	if filepath.Base(active) != enrolled.KeyID+".pem" {
		t.Fatalf("the active generation names key %s, it was created as %s", enrolled.KeyID, filepath.Base(active))
	}
}

func TestTheAgentSaysWhatItMayDoAsItStarts(t *testing.T) {
	logs := serveStopped(t, configured(t, stateDirectory(t), nil))
	reported, found := logged(t, logs, "agent_privileges")
	if !found {
		t.Fatalf("the agent said nothing about what it may do:\n%s", logs)
	}
	if reported["user"] != float64(os.Geteuid()) || reported["group"] != float64(os.Getegid()) {
		t.Errorf("the agent runs as uid %d in gid %d, and reported %v", os.Geteuid(), os.Getegid(), reported)
	}
	if _, said := reported["no_new_privs"]; !said || reported["groups"] == nil || reported["seccomp"] == "" || reported["seccomp"] == nil {
		t.Errorf("the agent left out part of what it may do: %v", reported)
	}
	beyond, _ := reported["beyond"].([]any)
	if os.Geteuid() == 0 {
		if reported["level"] != "WARN" || !slices.Contains(beyond, "superuser") {
			t.Fatalf("an agent running as the superuser reported %v", reported)
		}
		return
	}
	if reported["level"] != "INFO" || len(beyond) != 0 {
		t.Fatalf("an agent running as an account of its own reported %v", reported)
	}
}

func TestTheAgentWithholdsWhatItHoldsInMemoryAsItStarts(t *testing.T) {
	logs := serveStopped(t, configured(t, stateDirectory(t), nil))
	reported, found := logged(t, logs, "agent_core_dumps")
	if !found {
		t.Fatalf("the agent said nothing about what the kernel does with its memory:\n%s", logs)
	}
	if runtime.GOOS != "linux" {
		if reported["withheld"] != false || reported["level"] != "WARN" {
			t.Fatalf("an agent on %s reported %v", runtime.GOOS, reported)
		}
		return
	}
	if reported["withheld"] != true || reported["level"] != "INFO" {
		t.Fatalf("the agent reported %v", reported)
	}
	if _, said := logged(t, logs, "agent_privileges"); !said {
		t.Error("an agent that withheld its memory no longer says what it may do")
	}
}

func TestAnAgentTheKernelStillDumpsSaysWhatToDo(t *testing.T) {
	var logs bytes.Buffer
	memory(slog.New(slog.NewJSONHandler(&logs, nil)), errors.New("the kernel writes a core dump of the agent of up to 1024 bytes"))
	reported, found := logged(t, logs.String(), "agent_core_dumps")
	if !found || reported["level"] != "WARN" || reported["withheld"] != false {
		t.Fatalf("an agent the kernel still dumps reported %v", reported)
	}
	if hint, _ := reported["recovery"].(string); !strings.Contains(hint, "LimitCORE=0") {
		t.Errorf("the agent suggested %q", hint)
	}
}

func TestAnAgentHoldingMoreThanAnythingItDoesNeedsSaysSo(t *testing.T) {
	var logs bytes.Buffer
	privileged(slog.New(slog.NewJSONHandler(&logs, nil)), privileges.Privileges{
		User:         0,
		Group:        0,
		Groups:       []int{0},
		Capabilities: []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"},
	}, needed(config.Config{}))
	reported, found := logged(t, logs.String(), "agent_privileges")
	if !found || reported["level"] != "WARN" {
		t.Fatalf("an agent running as the superuser reported %v", reported)
	}
	beyond, _ := reported["beyond"].([]any)
	if !slices.Equal(beyond, []any{"superuser", "CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"}) {
		t.Errorf("the agent holds %v beyond what it needs", beyond)
	}
	if hint, _ := reported["recovery"].(string); !strings.Contains(hint, "account of its own") {
		t.Errorf("the agent suggested %q", hint)
	}
}

func TestAnAgentItsServiceKeepsFromItsStateDirectoryIsToldWhereItMayWrite(t *testing.T) {
	path := configured(t, stateDirectory(t), nil)
	unwritten := fmt.Errorf("create the installation state directory: %w", &fs.PathError{Op: "mkdir", Path: "/srv/seagull-agent", Err: syscall.EROFS})
	if hint := recovery(path, "/srv/seagull-agent", unwritten); !strings.Contains(hint, "/srv/seagull-agent") || !strings.Contains(hint, "ReadWritePaths=") {
		t.Fatalf("the agent suggested %q", hint)
	}
}

func TestAnAgentThatCannotSayWhichAccountItRunsAsIsToldWhatToDo(t *testing.T) {
	path := configured(t, stateDirectory(t), nil)
	started := fmt.Errorf("%w: uid 0 started it and it runs as uid 987", privileges.ErrInconsistent)
	if hint := recovery(path, "", started); !strings.Contains(hint, "setuid") {
		t.Fatalf("the agent suggested %q", hint)
	}
}

func TestAConfigurationTheAgentRefusesStopsItBeforeItTouchesTheInstallation(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, map[string]string{"spool": `{"max_age": "1000h"}`})
	var logs bytes.Buffer
	if code := serve(t.Context(), &logs, path); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	refused, found := logged(t, logs.String(), "agent_not_started")
	cause, _ := refused["error"].(string)
	hint, _ := refused["recovery"].(string)
	if !found || !strings.Contains(cause, "spool.max_age") || !strings.Contains(hint, "config check") {
		t.Fatalf("logged %v", refused)
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a configuration the agent refused reached the installation state: %v", err)
	}
}

func TestReadingTheConfigurationDoesNotStartTheAgent(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, map[string]string{"logging": `{"level": "debug"}`})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "config", "check"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), state) {
		t.Fatalf("exit code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	if code := run([]string{"-config", path, "config", "print"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	printed := map[string]any{}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		t.Fatalf("decode the printed configuration %q: %v", stdout.String(), err)
	}
	shown := func(group, setting string) any {
		held, _ := printed[group].(map[string]any)
		return held[setting]
	}
	if printed["format"] != float64(config.Format) || shown("logging", "level") != "debug" || shown("spool", "max_bytes") != "512MiB" {
		t.Fatalf("the agent printed %v", printed)
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading the configuration reached the installation state: %v", err)
	}

	refused := configured(t, state, map[string]string{"updates": `{"enabled": true}`})
	for _, command := range [][]string{{"config", "check"}, {"config", "print"}, {"platform", "check"}} {
		stdout.Reset()
		stderr.Reset()
		if code := run(append([]string{"-config", refused}, command...), &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Errorf("%q: exit code %d, stdout %q", command, code, stdout.String())
		}
		if !strings.Contains(stderr.String(), "updates.enabled") {
			t.Errorf("%q: refused the configuration with %q", command, stderr.String())
		}
	}
}

func TestCheckingThePlatformAuthenticatesItWithoutAnInstallation(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	platform := listening(t, trustBundle(path))
	ingest, renewal := platform.listen(t), platform.listen(t)
	rewrite(t, path, state, map[string]string{"server": servers(ingest.URL, renewal.URL, trustBundle(path))})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "platform", "check"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	for i, endpoint := range []struct{ name, address string }{{"ingest", ingest.URL}, {"renewal", renewal.URL}} {
		if i >= len(lines) || !strings.HasPrefix(lines[i], endpoint.name+" "+endpoint.address+" is authenticated: tls 1.3") ||
			!strings.Contains(lines[i], `"127.0.0.1"`) || !strings.Contains(lines[i], `issued by "Seagull platform"`) ||
			!strings.Contains(lines[i], "asks for the certificate of an enrolled agent") {
			t.Fatalf("the agent reported the platform as\n%s", stdout.String())
		}
	}
	if served := ingest.served.Load() + renewal.served.Load(); served != 0 {
		t.Fatalf("checking the platform sent it %d requests", served)
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checking the platform reached the installation state: %v", err)
	}
}

func TestAPlatformTheAgentCannotAuthenticateOrReachFailsTheCheck(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	listening(t, trustBundle(path))
	impostor := listening(t, filepath.Join(t.TempDir(), "impostor-ca.pem")).listen(t)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	unreachable := "https://" + closed.Addr().String()
	closed.Close()
	rewrite(t, path, state, map[string]string{"server": servers(impostor.URL, unreachable, trustBundle(path))})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "platform", "check"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("exit code %d, stdout %q", code, stdout.String())
	}
	for _, said := range []string{
		"seagull-agent: ingest: the platform could not be authenticated: " + impostor.URL,
		"holds the authority that issued the platform's certificate",
		"seagull-agent: renewal: the platform could not be reached: " + unreachable,
		"can be reached from this machine over the network",
	} {
		if !strings.Contains(stderr.String(), said) {
			t.Errorf("the agent did not say %q:\n%s", said, stderr.String())
		}
	}
	if impostor.served.Load() != 0 {
		t.Fatal("the agent sent a request to a platform it could not authenticate")
	}
}

func trustBundle(path string) string { return filepath.Join(filepath.Dir(path), "platform-ca.pem") }

func servers(ingest, renewal, bundle string) string {
	return fmt.Sprintf(`{"ingest_url": %q, "renewal_url": %q, "trust_bundle": %q}`, ingest, renewal, bundle)
}

type issuing struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	published   []byte
}

type served struct {
	*httptest.Server
	served atomic.Int32
	agent  atomic.Pointer[string]
}

// An authority for the platform, written where bundle says, and listeners it
// issued certificates for that ask every client for the certificate of an
// agent, as the platform's agent listeners do.
func listening(t *testing.T, bundle string) *issuing {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of the platform authority: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull platform"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign the certificate of the platform authority: %v", err)
	}
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write %s: %v", bundle, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate of the platform authority: %v", err)
	}
	return &issuing{certificate: certificate, key: key}
}

func (i *issuing) listen(t *testing.T) *served {
	t.Helper()
	listener := &served{}
	return i.serving(t, listener, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		listener.served.Add(1)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			listener.agent.Store(&r.TLS.PeerCertificates[0].Subject.CommonName)
		}
	}))
}

func (i *issuing) serving(t *testing.T, listener *served, handler http.Handler) *served {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of a listener: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ingest-gateway"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.certificate, key.Public(), i.key)
	if err != nil {
		t.Fatalf("issue the certificate of a listener: %v", err)
	}
	listener.Server = httptest.NewUnstartedServer(handler)
	listener.Config.ErrorLog = log.New(io.Discard, "", 0)
	agents := x509.NewCertPool()
	agents.AddCert(i.certificate)
	listener.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    agents,
	}
	listener.StartTLS()
	t.Cleanup(listener.Close)
	return listener
}

func TestTheAgentReadsItsConfigurationAgainWhenItIsAsked(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	var logs bytes.Buffer
	held := configuration{
		logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		path:   path,
		active: config.Activate(loaded(t, path)),
		level:  new(slog.LevelVar),
	}

	rewrite(t, path, state, map[string]string{"logging": `{"level": "debug"}`, "spool": `{"max_bytes": "1GiB"}`})
	reload(t, &held)

	reloaded, found := logged(t, logs.String(), "configuration_reloaded")
	if !found || reloaded["log_level"] != "debug" || reloaded["config"] != path {
		t.Fatalf("logged %v:\n%s", reloaded, logs.String())
	}
	if running := held.active.Settings(); running.Spool.MaxBytes != 1<<30 || running.Logging.Level != "debug" {
		t.Fatalf("the agent runs on %+v", running)
	}
	if held.level.Level() != slog.LevelDebug {
		t.Fatalf("the agent logs at %v", held.level.Level())
	}

	held.spool, _ = spoolIn(t, state)
	held.governor, _ = governor.New(held.logger, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", budget(held.active.Settings()))
	rewrite(t, path, state, map[string]string{
		"spool":     `{"max_bytes": "32MiB", "max_age": "400h"}`,
		"resources": `{"max_concurrent_scans": 3, "max_scan_bytes_per_second": "16MiB", "max_concurrent_uploads": 2}`,
		"transport": `{"max_upload_bytes_per_second": "2MiB"}`,
	})
	logs.Reset()
	reload(t, &held)
	spooled := held.spool.Stats()
	if spooled.MaxBytes != 32<<20 {
		t.Fatalf("after the reload the spool keeps to %d bytes", spooled.MaxBytes)
	}
	for _, stream := range spooled.Streams {
		if want := map[spool.Stream]time.Duration{spool.Events: 168 * time.Hour, spool.Inventory: 400 * time.Hour}[stream.Stream]; stream.MaxAge != want {
			t.Errorf("after the reload %s keeps records for %s, want %s", stream.Stream, stream.MaxAge, want)
		}
	}
	want := governor.Budget{Scans: 3, ScanBytesPerSecond: 16 << 20, Uploads: 2, UploadBytesPerSecond: 2 << 20}
	if governed := held.governor.Stats().Budget; governed != want {
		t.Fatalf("after the reload the governor keeps to %+v, want %+v", governed, want)
	}
	reported, found := logged(t, logs.String(), "agent_resources")
	spends, _ := reported["budgets"].(map[string]any)
	if !found || spends["max_concurrent_scans"] != float64(3) || spends["max_upload_bytes_per_second"] != float64(2<<20) {
		t.Fatalf("after the reload the agent reported what it spends as %v", reported)
	}
}

func reload(t *testing.T, held *configuration) {
	t.Helper()
	if err := held.reload(); err != nil {
		t.Fatalf("the agent stopped as it read its configuration again: %v", err)
	}
}

func TestTheSpoolKeepsNothingLongerOrLargerThanThePlatformTakes(t *testing.T) {
	for name, c := range map[string]struct {
		kept              time.Duration
		events, inventory time.Duration
	}{
		"a day":       {kept: 24 * time.Hour, events: 24 * time.Hour, inventory: 24 * time.Hour},
		"a fortnight": {kept: 336 * time.Hour, events: 168 * time.Hour, inventory: 336 * time.Hour},
		"thirty days": {kept: 720 * time.Hour, events: 168 * time.Hour, inventory: 720 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			settings := loaded(t, configured(t, stateDirectory(t), map[string]string{
				"spool":     fmt.Sprintf(`{"max_age": %q}`, c.kept),
				"transport": `{"max_batch_bytes": "2MiB"}`,
			}))
			held := limits(settings)
			if held.MaxAge[spool.Events] != c.events || held.MaxAge[spool.Inventory] != c.inventory {
				t.Fatalf("a spool kept for %s keeps events for %s and inventory for %s", c.kept, held.MaxAge[spool.Events], held.MaxAge[spool.Inventory])
			}
			if held.MaxRecordBytes != 2<<20-protocol.BatchEnvelopeBytes || held.MaxBytes != 512<<20 {
				t.Fatalf("the spool keeps records of up to %d bytes in %d", held.MaxRecordBytes, held.MaxBytes)
			}
		})
	}
}

func TestAReloadTheAgentRefusesKeepsTheConfigurationItRunsOn(t *testing.T) {
	for name, ask := range map[string]func(t *testing.T, path, state string){
		"a configuration it refuses": func(t *testing.T, path, state string) {
			rewrite(t, path, state, map[string]string{"logging": `{"level": "silent"}`})
		},
		"a setting it settled as it started": func(t *testing.T, path, state string) {
			rewrite(t, path, filepath.Join(state, "elsewhere"), nil)
		},
		"a configuration that is gone": func(t *testing.T, path, state string) {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
		},
		"a configuration another account can change": func(t *testing.T, path, state string) {
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatalf("expose %s: %v", path, err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := stateDirectory(t)
			path := configured(t, state, nil)
			started := loaded(t, path)
			var logs bytes.Buffer
			held := configuration{
				logger: slog.New(slog.NewJSONHandler(&logs, nil)),
				path:   path,
				active: config.Activate(started),
				level:  new(slog.LevelVar),
			}
			held.level.Set(started.Logging.Severity())

			ask(t, path, state)
			reload(t, &held)

			refused, found := logged(t, logs.String(), "configuration_not_reloaded")
			if !found || refused["level"] != "ERROR" || refused["recovery"] == nil {
				t.Fatalf("logged %v:\n%s", refused, logs.String())
			}
			if running := held.active.Settings(); !reflect.DeepEqual(running, started) {
				t.Fatalf("the agent runs on\n%+v\nrather than the configuration it started with\n%+v", running, started)
			}
			if held.level.Level() != started.Logging.Severity() {
				t.Fatalf("the agent logs at %v, it started at %v", held.level.Level(), started.Logging.Severity())
			}
		})
	}
}

// What one line the agent writes may carry of what it read: enough to name
// what it refuses, and never enough for a file to decide how long a log is.
const maxLineBytes = 8 << 10

func TestNothingTheAgentReadsReachesWhatItWrites(t *testing.T) {
	const password = "p4ssw0rd-token"
	marker := strings.Repeat("written", 36) + "-marker-tail"
	for name, prepare := range map[string]func(t *testing.T, state string) string{
		"a setting this agent does not have": func(t *testing.T, state string) string {
			return configured(t, state, map[string]string{marker: "true"})
		},
		"a listener that carries a credential": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			rewrite(t, path, state, map[string]string{"server": fmt.Sprintf(
				`{"ingest_url": "https://agent:%s@gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q}`,
				password, filepath.Join(filepath.Dir(path), "platform-ca.pem"))})
			return path
		},
		"a trust bundle that holds something else": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			bundle := filepath.Join(filepath.Dir(path), "platform-ca.pem")
			if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte("not a certificate")}), 0o644); err != nil {
				t.Fatalf("write %s: %v", bundle, err)
			}
			return path
		},
		"an installation state that is damaged": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatalf("create %s: %v", state, err)
			}
			held := fmt.Sprintf(`{"format": 1, "installation_id": %q}`, marker)
			if err := os.WriteFile(filepath.Join(state, "installation.json"), []byte(held), 0o600); err != nil {
				t.Fatalf("damage the installation state: %v", err)
			}
			return path
		},
		"a key that is not one": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			active := enroll(t, path).key
			if err := os.WriteFile(active, pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte("not a key")}), 0o600); err != nil {
				t.Fatalf("damage the key: %v", err)
			}
			return path
		},
		"a certificate that is not one": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			active := enroll(t, path).certificate
			if err := os.WriteFile(active, pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte("not a certificate")}), 0o600); err != nil {
				t.Fatalf("damage the certificate: %v", err)
			}
			return path
		},
		"a spool that holds what the agent did not write": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			_, release := spoolIn(t, state)
			release()
			stray := filepath.Join(state, spoolDirectory, "events", strings.Repeat("written", 30)+"-marker-tail")
			if err := os.WriteFile(stray, []byte(password), 0o600); err != nil {
				t.Fatalf("write %s: %v", stray, err)
			}
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := stateDirectory(t)
			path := prepare(t, state)
			var logs, stdout, stderr bytes.Buffer
			if code := serve(t.Context(), &logs, path); code != 1 {
				t.Fatalf("exit code %d, want 1:\n%s", code, logs.String())
			}
			run([]string{"-config", path, "config", "check"}, &stdout, &stderr)
			run([]string{"-config", path, "config", "print"}, &stdout, &stderr)
			written := logs.String() + stdout.String() + stderr.String()
			if strings.Contains(written, "-marker-tail") || strings.Contains(written, password) {
				t.Errorf("the agent wrote down what it read:\n%s", written)
			}
			for line := range strings.Lines(written) {
				if len(line) > maxLineBytes {
					t.Errorf("the agent wrote a line of %d bytes, and what it reads decides how long it is:\n%s", len(line), line)
				}
			}
		})
	}
}

// A record holds whatever a collector admitted, so what the agent writes about
// the spool that keeps it names records by where they are and never by what
// they hold, even when it cannot read them back.
func TestNothingTheSpoolHoldsReachesWhatTheAgentWrites(t *testing.T) {
	const password = "p4ssw0rd-token"
	state := stateDirectory(t)
	path := configured(t, state, nil)
	held, release := spoolIn(t, state)
	for n := range 3 {
		secret := spool.Record{ID: fmt.Sprintf("session-%d-marker-tail", n), Payload: []byte(strings.Repeat(password+" ", 40))}
		if _, err := held.Admit(spool.Events, secret); err != nil {
			t.Fatalf("admit a record: %v", err)
		}
	}
	release()
	segments, err := filepath.Glob(filepath.Join(state, spoolDirectory, "events", "*.seg"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("the spool holds %q: %v", segments, err)
	}
	file, err := os.OpenFile(segments[0], os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", segments[0], err)
	}
	described, err := file.Stat()
	if err == nil {
		_, err = file.WriteAt([]byte("damaged"), described.Size()-100)
	}
	if err = errors.Join(err, file.Close()); err != nil {
		t.Fatalf("damage %s: %v", segments[0], err)
	}
	if err := os.WriteFile(filepath.Join(state, spoolDirectory, "events", "ledger"), []byte(password), 0o600); err != nil {
		t.Fatalf("damage the ledger: %v", err)
	}

	logs := serveStopped(t, path)
	if _, found := logged(t, logs, "spool_records_lost"); !found {
		t.Fatalf("the agent did not report the record it could not read back:\n%s", logs)
	}
	if _, found := logged(t, logs, "spool_acknowledgements_lost"); !found {
		t.Fatalf("the agent did not report the ledger it could not read back:\n%s", logs)
	}
	if strings.Contains(logs, password) || strings.Contains(logs, "marker-tail") {
		t.Fatalf("the agent wrote down what its spool holds:\n%s", logs)
	}
}

func TestEverythingTheInstallationHoldsIsPrivateToTheAccountTheAgentRunsAs(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	enroll(t, path)
	serveStopped(t, path)
	kept, release := spoolIn(t, state)
	for _, stream := range []spool.Stream{spool.Events, spool.Inventory} {
		if _, err := kept.Admit(stream, spool.Record{ID: "record-1", Payload: []byte("kept")}); err != nil {
			t.Fatalf("admit a record: %v", err)
		}
	}
	release()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "installation", "replace"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	serveStopped(t, path)

	held := 0
	err := filepath.WalkDir(state, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		held++
		described, err := entry.Info()
		if err != nil {
			return err
		}
		if err := files.Private(described); err != nil {
			if errors.Is(err, errors.ErrUnsupported) {
				t.Skipf("this platform cannot tell who may reach %s", path)
			}
			t.Errorf("%s %v", path, err)
		}
		switch permissions := described.Mode().Perm(); {
		case entry.IsDir() && permissions != 0o700:
			t.Errorf("%s is a directory granting %s, and the installation keeps its own as 0700", path, permissions)
		case !entry.IsDir() && !described.Mode().IsRegular():
			t.Errorf("%s is neither a file nor a directory of the installation", path)
		case !entry.IsDir() && permissions != 0o600:
			t.Errorf("%s grants %s, and the installation keeps what it holds as 0600", path, permissions)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", state, err)
	}
	if held < 16 {
		t.Fatalf("an enrolled installation that was replaced holds %d files and directories", held)
	}
}

func TestTheAgentSaysWhatItSpendsApartFromWhatBoundsIt(t *testing.T) {
	path := configured(t, stateDirectory(t), map[string]string{
		"resources": `{"memory_limit": "128MiB", "max_concurrent_scans": 3, "max_scan_bytes_per_second": "4MiB", "max_concurrent_uploads": 2}`,
	})
	reported, found := logged(t, serveStopped(t, path), "agent_resources")
	if !found {
		t.Fatal("the agent did not say what it spends and what bounds it")
	}
	want := map[string]any{
		"memory_limit":                float64(128 << 20),
		"max_concurrent_scans":        float64(3),
		"max_scan_bytes_per_second":   float64(4 << 20),
		"max_concurrent_uploads":      float64(2),
		"max_upload_bytes_per_second": float64(1 << 20),
	}
	if spends, _ := reported["budgets"].(map[string]any); !maps.Equal(spends, want) {
		t.Fatalf("the agent reported its budgets as %v, want %v", spends, want)
	}
	if reported["processors"] != float64(runtime.GOMAXPROCS(0)) {
		t.Errorf("the agent reported %v processors, and Go runs it on %d", reported["processors"], runtime.GOMAXPROCS(0))
	}
	enforced, err := ceilings.Enforced()
	if err != nil {
		if reported["level"] != "WARN" || reported["error"] == nil || reported["recovery"] == nil {
			t.Fatalf("an agent that cannot tell what bounds it reported %v", reported)
		}
		return
	}
	bounds, _ := reported["ceilings"].(map[string]any)
	if enforced.Descriptors > 0 && bounds["descriptors"] != float64(enforced.Descriptors) {
		t.Errorf("the agent reported the ceilings %v, and the process may open %d descriptors", bounds, enforced.Descriptors)
	}
	if enforced.Memory > 0 && bounds["memory"] != float64(enforced.Memory) {
		t.Errorf("the agent reported the ceilings %v, and its cgroup may hold %d bytes", bounds, enforced.Memory)
	}
	unenforced, _ := reported["unenforced"].([]any)
	if len(unenforced) != len(enforced.Unenforced()) {
		t.Errorf("the agent reported %v as unenforced, and %v are", unenforced, enforced.Unenforced())
	}
	if warned := len(enforced.Unenforced()) > 0 || enforced.Memory <= 128<<20; warned != (reported["level"] == "WARN") {
		t.Errorf("the agent reported what bounds it at %v, with %v unenforced and a memory ceiling of %d", reported["level"], unenforced, enforced.Memory)
	}
}

func TestAMemoryTargetTheKernelWouldCutShortIsReported(t *testing.T) {
	settings := loaded(t, configured(t, stateDirectory(t), map[string]string{"resources": `{"memory_limit": "256MiB"}`}))
	bounded := ceilings.Ceilings{Memory: 1 << 30, CPUs: 1.5, Tasks: 512, Descriptors: 1 << 16}
	for name, c := range map[string]struct {
		enforced   ceilings.Ceilings
		err        error
		level      string
		unenforced []any
		says       string
	}{
		"a service that bounds everything": {enforced: bounded, level: "INFO", unenforced: []any{}},
		"a memory ceiling below the target": {
			enforced: ceilings.Ceilings{Memory: 128 << 20, CPUs: 1.5, Tasks: 512, Descriptors: 1 << 16}, level: "WARN", unenforced: []any{},
			says: "the kernel stops it before the garbage collector works to it",
		},
		"a memory ceiling equal to the target": {
			enforced: ceilings.Ceilings{Memory: 256 << 20, CPUs: 1.5, Tasks: 512, Descriptors: 1 << 16}, level: "WARN", unenforced: []any{},
			says: "is not below the memory the agent may hold",
		},
		"nothing that bounds it":         {level: "WARN", unenforced: []any{"memory", "cpu", "tasks", "descriptors"}},
		"a platform that cannot tell it": {err: errors.ErrUnsupported, level: "WARN"},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			spending(slog.New(slog.NewJSONHandler(&logs, nil)), settings, c.enforced, c.err)
			reported, _ := logged(t, logs.String(), "agent_resources")
			if reported["level"] != c.level || (c.level == "WARN") != (reported["recovery"] != nil) {
				t.Fatalf("reported %v", reported)
			}
			if unenforced, _ := reported["unenforced"].([]any); c.err == nil && !slices.Equal(unenforced, c.unenforced) {
				t.Errorf("reported %v as unenforced, want %v", unenforced, c.unenforced)
			}
			if note, _ := reported["reason"].(string); !strings.Contains(note, c.says) || (c.says == "") != (note == "") {
				t.Errorf("reported the memory target as %q", note)
			}
			if c.err != nil && (reported["error"] == nil || reported["ceilings"] != nil) {
				t.Errorf("a platform that cannot tell what bounds the agent reported %v", reported)
			}
		})
	}
}

func TestTheAgentSpendsWhatItsConfigurationAllows(t *testing.T) {
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })

	settings := loaded(t, configured(t, stateDirectory(t), map[string]string{
		"logging":   `{"level": "warn"}`,
		"resources": `{"memory_limit": "512MiB"}`,
	}))
	level := new(slog.LevelVar)
	apply(settings, level)
	if level.Level() != slog.LevelWarn {
		t.Errorf("the agent logs at %v, its configuration says %q", level.Level(), settings.Logging.Level)
	}
	if limit := debug.SetMemoryLimit(-1); limit != 512<<20 {
		t.Errorf("the agent keeps to %d bytes, its configuration allows %s", limit, settings.Resources.MemoryLimit)
	}
}

func TestAHangupAsksTheAgentToReadItsConfigurationAgain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot deliver SIGHUP to another process")
	}
	state := stateDirectory(t)
	path := configured(t, state, nil)
	agent := exec.CommandContext(t.Context(), os.Args[0])
	agent.Env = append(os.Environ(), childArguments+"=-config "+path+" run")
	logs, err := agent.StderrPipe()
	if err != nil {
		t.Fatalf("attach to the agent's log: %v", err)
	}
	if err := agent.Start(); err != nil {
		t.Fatalf("start the agent: %v", err)
	}
	entries := follow(t, logs)
	await(t, entries, "agent_starting")

	rewrite(t, path, state, map[string]string{"spool": `{"max_bytes": "1MiB"}`})
	hangup(t, agent)
	if cause, _ := await(t, entries, "configuration_not_reloaded")["error"].(string); !strings.Contains(cause, "spool.max_bytes") {
		t.Errorf("the agent refused the configuration with %q", cause)
	}

	rewrite(t, path, state, map[string]string{"spool": `{"max_bytes": "1GiB"}`})
	hangup(t, agent)
	if entry := await(t, entries, "configuration_reloaded"); entry["config"] != path {
		t.Errorf("the agent read %v", entry["config"])
	}

	if err := agent.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	await(t, entries, "agent_stopped")
	for range entries {
	}
	if err := agent.Wait(); err != nil {
		t.Fatalf("the agent exited with %v after a reload, want a clean exit", err)
	}
}

func TestTheAgentCollectsAuthenticationWhileItsConfigurationNamesIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot deliver SIGHUP to another process")
	}
	state := stateDirectory(t)
	path := configured(t, state, map[string]string{"modules": `{"authentication": {"enabled": true}}`})
	agent := exec.CommandContext(t.Context(), os.Args[0])
	agent.Env = append(os.Environ(), childArguments+"=-config "+path+" run")
	logs, err := agent.StderrPipe()
	if err != nil {
		t.Fatalf("attach to the agent's log: %v", err)
	}
	if err := agent.Start(); err != nil {
		t.Fatalf("start the agent: %v", err)
	}
	entries := follow(t, logs)
	if started := await(t, entries, "module_started"); started["module"] != "authentication" || started["state"] != "running" {
		t.Errorf("the agent started %v", started)
	}
	if listed, err := os.ReadDir(filepath.Join(state, "collection")); err != nil {
		t.Errorf("the agent keeps no place of its collectors: %v %v", listed, err)
	}

	rewrite(t, path, state, map[string]string{"modules": `{"authentication": {"enabled": false}}`})
	hangup(t, agent)
	if stopped := await(t, entries, "module_stopped"); stopped["module"] != "authentication" {
		t.Errorf("the agent stopped %v", stopped)
	}
	await(t, entries, "configuration_reloaded")

	rewrite(t, path, state, map[string]string{"modules": `{"authentication": {"enabled": true}, "fim": {"enabled": true}}`})
	hangup(t, agent)
	if cause, _ := await(t, entries, "configuration_not_reloaded")["error"].(string); !strings.Contains(cause, "modules.fim is configured, and this build collects with authentication") {
		t.Errorf("the agent refused the configuration with %q", cause)
	}

	rewrite(t, path, state, map[string]string{"modules": `{"authentication": {"enabled": true}}`})
	hangup(t, agent)
	if started := await(t, entries, "module_started"); started["module"] != "authentication" {
		t.Errorf("the agent started %v", started)
	}

	if err := agent.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	await(t, entries, "agent_stopped")
	for range entries {
	}
	if err := agent.Wait(); err != nil {
		t.Fatalf("the agent exited with %v, want a clean exit", err)
	}
}

func TestTheAgentTakesStockOfThisHostOnceAndAgainOnlyWhenItChanges(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent takes stock of linux hosts")
	}
	state := stateDirectory(t)
	path := configured(t, state, map[string]string{"modules": `{"inventory": {"enabled": true}}`, "logging": `{"level": "debug"}`})
	entries, stop := running(t, path)
	if started := await(t, entries, "module_started"); started["module"] != "inventory" || started["state"] != "running" {
		t.Errorf("the agent started %v", started)
	}
	admitted, round := taking(t, entries)
	want := []string{"operating_system", "kernel", "hardware", "network_interface", "user"}
	if _, err := os.Stat("/usr/bin/dpkg-query"); err == nil {
		want = append(want, "package")
	}
	for _, kind := range want {
		if !slices.Contains(admitted, kind) {
			t.Errorf("taking stock of this host the agent admitted %v, and it has %s", admitted, kind)
		}
	}
	if round["admitted"] != float64(len(admitted)) {
		t.Errorf("the agent ended its round with %v after admitting %v", round, admitted)
	}
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}

	entries, stop = running(t, path)
	opened := await(t, entries, "spool_opened")
	if held, _ := opened["inventory"].(map[string]any); held["outstanding"] != float64(len(admitted)) {
		t.Errorf("started again, the agent's spool holds %v", opened["inventory"])
	}
	again, round := taking(t, entries)
	for _, kind := range []string{"operating_system", "kernel", "package", "user"} {
		if slices.Contains(again, kind) {
			t.Errorf("started again on a host whose %s did not change, the agent admitted %v", kind, again)
		}
	}
	if round["admitted"] != float64(len(again)) {
		t.Errorf("the agent ended its round with %v after admitting %v", round, again)
	}
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
}

func TestTheAgentTakesStockOfTheProcessesItSeesAsAModuleOfTheirOwn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent takes stock of the processes of linux hosts")
	}
	state := stateDirectory(t)
	path := configured(t, state, map[string]string{"modules": `{"processes": {"enabled": true}}`, "logging": `{"level": "debug"}`})
	entries, stop := running(t, path)
	if started := await(t, entries, "module_started"); started["module"] != "processes" || started["state"] != "running" {
		t.Errorf("the agent started %v", started)
	}
	admitted, round := taking(t, entries)
	if !slices.Equal(admitted, []string{"process"}) || round["module"] != "processes" {
		t.Errorf("taking stock of the processes the agent admitted %v and ended with %v", admitted, round)
	}
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
	root, err := os.OpenRoot(filepath.Join(state, spoolDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	kept, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	held, err := kept.Read(spool.Inventory, 1, 16, 64<<20)
	if err != nil || len(held) != 1 {
		t.Fatalf("the spool holds %d inventory records: %v", len(held), err)
	}
	record := &inventoryv1.Record{}
	if err := proto.Unmarshal(held[0].Payload, record); err != nil || record.GetKind() != inventoryv1.Kind_KIND_PROCESS || record.GetCollection().GetCollector() != "processes" {
		t.Fatalf("the spool holds %v: %v", record, err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pids := map[uint32]*inventoryv1.Process{}
	for _, item := range record.GetItems() {
		pids[item.GetProcess().GetPid()] = item.GetProcess()
		if item.GetProcess().GetCommandLine() != "" {
			t.Errorf("the agent took the command line of %v", item.GetProcess())
		}
	}
	own := pids[uint32(os.Getpid())]
	if own.GetPath() != executable || own.GetParentPid() != uint32(os.Getppid()) || pids[1] == nil || pids[uint32(os.Getppid())] == nil {
		t.Errorf("of %d processes, the agent took itself as %v", len(pids), own)
	}
}

// taking reads the log of a round of the inventory collector: the kinds it
// admitted, and how it said the round ended.
func taking(t *testing.T, entries <-chan map[string]any) ([]string, map[string]any) {
	t.Helper()
	var admitted []string
	timeout := time.After(time.Minute)
	for {
		select {
		case entry, open := <-entries:
			if !open {
				t.Fatal("the agent stopped before it took stock")
			}
			switch entry["msg"] {
			case "inventory_admitted":
				admitted = append(admitted, fmt.Sprint(entry["kind"]))
			case "inventory_taken":
				return admitted, entry
			}
		case <-timeout:
			t.Fatal("the agent took no stock within a minute")
		}
	}
}

func hangup(t *testing.T, agent *exec.Cmd) {
	t.Helper()
	if err := agent.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
}

func loaded(t *testing.T, path string) config.Config {
	t.Helper()
	settings, err := config.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return settings
}

func TestAnythingButACommandIsAUsageError(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	for _, args := range [][]string{
		nil,
		{"start"},
		{"-verbose"},
		{"-version", "extra"},
		{"-version", "run"},
		{"run"},
		{"run", "extra"},
		{"-config", path},
		{"-config", path, "-version"},
		{"-config", path, "run", "extra"},
		{"-config", path, "config"},
		{"-config", path, "config", "reload"},
		{"-config", path, "installation"},
		{"-config", path, "installation", "show"},
		{"-config", path, "platform"},
		{"-config", path, "platform", "check", "extra"},
		{"-config", path, "enrollment"},
		{"-config", path, "enrollment", "request"},
		{"-config", path, "enrollment", "request", "web-01", "extra"},
		{"-config", path, "enrollment", "import"},
		{"-config", path, "enrollment", "renew", "web-01"},
		{"-version", "enrollment", "request", "web-01"},
		{"-config", path, "diagnostics"},
		{"-config", path, "diagnostics", "bundle.json", "extra"},
		{"-version", "diagnostics", "bundle.json"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit code %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%q: wrote %q to stdout", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "seagull-agent -config FILE run") {
			t.Errorf("%q: explained no command on stderr: %q", args, stderr.String())
		}
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a usage error touched the installation state: %v", err)
	}
}

func TestReplacingTheInstallationNamesTheOneItReplaces(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	created, _ := logged(t, serveStopped(t, path), "installation_created")
	previous, _ := created["installation_id"].(string)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "installation", "replace"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	replacement, replaces, _ := strings.Cut(strings.TrimPrefix(stdout.String(), "installation_id "), "\n")
	if previous == "" || replacement == previous || replaces != "replaces "+previous+"\n" {
		t.Fatalf("printed %q after replacing %q", stdout.String(), previous)
	}
	if !strings.Contains(stderr.String(), "enroll the new installation with") || !strings.Contains(stderr.String(), "enrollment request AGENT_ID") {
		t.Errorf("said nothing about enrolling the new installation: %q", stderr.String())
	}
	if started, _ := logged(t, serveStopped(t, path), "agent_starting"); started["installation_id"] != replacement {
		t.Fatalf("started as installation %v after replacing it with %s", started["installation_id"], replacement)
	}
}

func TestTheReplacementTheAgentSuggestsLetsItStartAgain(t *testing.T) {
	for name, prepare := range map[string]func(state string) error{
		"a damaged installation state": func(state string) error {
			return os.WriteFile(filepath.Join(state, "installation.json"), []byte("{"), 0o600)
		},
		"a directory that lost its installation state": func(state string) error {
			return os.Mkdir(filepath.Join(state, "keys"), 0o700)
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := stateDirectory(t)
			path := configured(t, state, nil)
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatalf("create %s: %v", state, err)
			}
			if err := prepare(state); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			var logs bytes.Buffer
			if code := serve(t.Context(), &logs, path); code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			refused, _ := logged(t, logs.String(), "agent_not_started")
			suggested := fmt.Sprintf(`"seagull-agent -config %s installation replace"`, path)
			if recovery, _ := refused["recovery"].(string); !strings.Contains(recovery, suggested) {
				t.Fatalf("the agent suggested %q, want %s", recovery, suggested)
			}

			var stdout, stderr bytes.Buffer
			if code := run([]string{"-config", path, "installation", "replace"}, &stdout, &stderr); code != 0 {
				t.Fatalf("the suggested replacement exited with %d: %s", code, stderr.String())
			}
			if _, started := logged(t, serveStopped(t, path), "agent_starting"); !started {
				t.Fatal("the agent did not start after the suggested replacement")
			}
		})
	}
}

func TestThereIsNoInstallationToReplaceBeforeTheAgentRuns(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", configured(t, stateDirectory(t), nil), "installation", "replace"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "no installation to replace") ||
		!strings.Contains(stderr.String(), "run the agent to create an installation") {
		t.Fatalf("printed %q and %q", stdout.String(), stderr.String())
	}
}

func TestASignalStopsTheAgentCleanly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot deliver SIGINT or SIGTERM to another process")
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(signal.String(), func(t *testing.T) {
			agent := exec.CommandContext(t.Context(), os.Args[0])
			agent.Env = append(os.Environ(), childArguments+"=-config "+configured(t, stateDirectory(t), nil)+" run")
			logs, err := agent.StderrPipe()
			if err != nil {
				t.Fatalf("attach to the agent's log: %v", err)
			}
			if err := agent.Start(); err != nil {
				t.Fatalf("start the agent: %v", err)
			}
			entries := follow(t, logs)
			await(t, entries, "agent_starting")

			if err := agent.Process.Signal(signal); err != nil {
				t.Fatalf("send %s: %v", signal, err)
			}
			if reason := await(t, entries, "shutdown_started")["reason"]; reason != signal.String()+" signal received" {
				t.Errorf("the agent logged %q as the reason it stopped", reason)
			}
			await(t, entries, "agent_stopped")
			for range entries {
			}
			if err := agent.Wait(); err != nil {
				t.Fatalf("the agent exited with %v after %s, want a clean exit", err, signal)
			}
		})
	}
}

func TestTheAgentExitsWithAnErrorWhenItCannotRun(t *testing.T) {
	cases := []struct {
		name       string
		components []agentruntime.Component
		prepare    func(t *testing.T, path, state string)
		message    string
		cause      string
		recovery   string
	}{
		{
			name: "an essential component failed",
			components: []agentruntime.Component{{Name: "delivery", Policy: agentruntime.Essential, Run: func(context.Context) error {
				return errors.New("spool unavailable")
			}}},
			message: "agent_stopped",
			cause:   "delivery: spool unavailable",
		},
		{
			name: "the composition is incomplete",
			components: []agentruntime.Component{{Name: "delivery", Run: func(context.Context) error {
				return nil
			}}},
			message: "agent_not_started",
			cause:   "delivery declares no failure policy",
		},
		{
			name: "the installation state is damaged",
			prepare: func(t *testing.T, path, state string) {
				if err := os.Mkdir(state, 0o700); err != nil {
					t.Fatalf("create %s: %v", state, err)
				}
				if err := os.WriteFile(filepath.Join(state, "installation.json"), []byte("{"), 0o600); err != nil {
					t.Fatalf("damage the installation state: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the installation state is damaged",
			recovery: "installation replace",
		},
		{
			name: "the key of the active credential generation is missing",
			prepare: func(t *testing.T, path, state string) {
				if err := os.Remove(enroll(t, path).key); err != nil {
					t.Fatalf("lose the key: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the key does not exist",
			recovery: "enrollment request AGENT_ID",
		},
		{
			name: "the key of the active credential generation is damaged",
			prepare: func(t *testing.T, path, state string) {
				if err := os.WriteFile(enroll(t, path).key, []byte("damaged"), 0o600); err != nil {
					t.Fatalf("damage the key: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the key is damaged",
			recovery: "enrollment request AGENT_ID",
		},
		{
			name: "another account can read the key",
			prepare: func(t *testing.T, path, state string) {
				if err := os.Chmod(enroll(t, path).key, 0o644); err != nil {
					t.Fatalf("expose the key: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the key is not private to the account the agent runs as",
			recovery: "revoke the certificate issued for it",
		},
		{
			name: "the certificate of the active credential generation is missing",
			prepare: func(t *testing.T, path, state string) {
				if err := os.Remove(enroll(t, path).certificate); err != nil {
					t.Fatalf("lose the certificate: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the certificate does not exist",
			recovery: "enrollment import ISSUED",
		},
		{
			name: "the certificate of the active credential generation is damaged",
			prepare: func(t *testing.T, path, state string) {
				if err := os.WriteFile(enroll(t, path).certificate, []byte("damaged"), 0o600); err != nil {
					t.Fatalf("damage the certificate: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the certificate is damaged",
			recovery: "enrollment request AGENT_ID",
		},
		{
			name: "the certificate of the active credential generation was issued for another key",
			prepare: func(t *testing.T, path, state string) {
				active := enroll(t, path)
				other := filepath.Join(t.TempDir(), "other")
				if err := os.Mkdir(other, 0o700); err != nil {
					t.Fatalf("create %s: %v", other, err)
				}
				replaced := configured(t, other, nil)
				stranger := enrollWith(t, replaced, listening(t, trustBundle(replaced)))
				content, err := os.ReadFile(stranger.certificate)
				if err == nil {
					err = os.WriteFile(active.certificate, content, 0o600)
				}
				if err != nil {
					t.Fatalf("swap the certificate: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the certificate is damaged",
			recovery: "enrollment request AGENT_ID",
		},
		{
			name: "another account can change the certificate",
			prepare: func(t *testing.T, path, state string) {
				if err := os.Chmod(enroll(t, path).certificate, 0o660); err != nil {
					t.Fatalf("expose the certificate: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the certificate is not private to the account the agent runs as",
			recovery: "make %s and everything in it belong to the account the agent runs as",
		},
		{
			name: "another account can list the keys",
			prepare: func(t *testing.T, path, state string) {
				enroll(t, path)
				if err := os.Chmod(filepath.Join(state, "keys"), 0o750); err != nil {
					t.Fatalf("expose the keys: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the installation state is not private to the account the agent runs as",
			recovery: "make %s and everything in it belong to the account the agent runs as",
		},
		{
			name: "another account can read the spool",
			prepare: func(t *testing.T, path, state string) {
				_, release := spoolIn(t, state)
				release()
				if err := os.Chmod(filepath.Join(state, spoolDirectory, "inventory", "ledger"), 0o644); err != nil {
					t.Fatalf("expose the spool: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the spool is not private to the account the agent runs as",
			recovery: "make %s and everything in it belong to the account the agent runs as",
		},
		{
			name: "the spool holds what the agent did not write",
			prepare: func(t *testing.T, path, state string) {
				_, release := spoolIn(t, state)
				release()
				if err := os.Mkdir(filepath.Join(state, spoolDirectory, "processes"), 0o700); err != nil {
					t.Fatalf("add to the spool: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the spool holds what it did not write",
			recovery: "take out of %s/spool what the agent did not write there",
		},
		{
			name: "the spool was written by a newer agent",
			prepare: func(t *testing.T, path, state string) {
				_, release := spoolIn(t, state)
				release()
				if err := os.WriteFile(filepath.Join(state, spoolDirectory, "events", "ledger"), []byte("SGLG\x03\x00"+strings.Repeat("\x00", 40)), 0o600); err != nil {
					t.Fatalf("write a newer ledger: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the spool was written by a newer agent",
			recovery: "run the agent release that wrote this state",
		},
		{
			name: "another agent holds the installation",
			prepare: func(t *testing.T, path, state string) {
				held, err := identity.Open(state)
				if err != nil {
					t.Fatalf("hold the installation: %v", err)
				}
				t.Cleanup(func() { _ = held.Close() })
			},
			message:  "agent_not_started",
			cause:    "another agent process holds the installation state",
			recovery: "stop the agent that holds %s",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := stateDirectory(t)
			path := configured(t, state, nil)
			if c.prepare != nil {
				c.prepare(t, path, state)
			}
			var logs bytes.Buffer
			if code := serve(t.Context(), &logs, path, c.components...); code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			entry, found := logged(t, logs.String(), c.message)
			if !found {
				t.Fatalf("logged no %s:\n%s", c.message, logs.String())
			}
			cause, _ := entry["error"].(string)
			recovery, _ := entry["recovery"].(string)
			if want := strings.ReplaceAll(c.recovery, "%s", state); entry["level"] != "ERROR" ||
				!strings.Contains(cause, c.cause) || !strings.Contains(recovery, want) {
				t.Fatalf("logged %v, want an error naming %q and a recovery naming %q", entry, c.cause, want)
			}
			if exposesKeys(t, logs.String(), state) {
				t.Fatalf("the log shows a key:\n%s", logs.String())
			}
		})
	}
}

type enrolled struct {
	key         string
	certificate string
}

func enroll(t *testing.T, path string) enrolled {
	t.Helper()
	return enrollWith(t, path, listening(t, trustBundle(path)))
}

func enrollWith(t *testing.T, path string, signing *issuing) enrolled {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "enrollment", "request", "web-01"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ask for a certificate: exit code %d: %s", code, stderr.String())
	}
	answer := saved(t, signing.issue(t, stdout.Bytes(), nil))
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-config", path, "enrollment", "import", answer}, &stdout, &stderr); code != 0 {
		t.Fatalf("import the certificate: exit code %d: %s", code, stderr.String())
	}
	state := loaded(t, path).Identity.StateDirectory
	installation, err := identity.Open(state)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	defer installation.Close()
	active, ok := installation.Enrollment()
	if !ok {
		t.Fatal("the import enrolled nothing")
	}
	return enrolled{
		key:         filepath.Join(state, keysDirectory, active.KeyID+".pem"),
		certificate: filepath.Join(state, certificatesDirectory, active.Certificate.FingerprintSHA256+".pem"),
	}
}

func (i *issuing) issue(t *testing.T, requested []byte, change func(*x509.Certificate)) []byte {
	t.Helper()
	encoded, err := i.issued(requested, "", change)
	if err != nil {
		t.Fatalf("issue a certificate: %v", err)
	}
	return encoded
}

func (i *issuing) issued(requested []byte, agentID string, change func(*x509.Certificate)) ([]byte, error) {
	block, _ := pem.Decode(requested)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("the agent asked with %q", requested)
	}
	asked, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || asked.CheckSignature() != nil {
		return nil, fmt.Errorf("the agent asked with a request that does not verify: %v", err)
	}
	if agentID != "" && asked.Subject.CommonName != agentID {
		return nil, fmt.Errorf("the request names %s and the connection %s", asked.Subject.CommonName, agentID)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: asked.Subject.CommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              i.certificate.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if change != nil {
		change(template)
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, i.certificate, asked.PublicKey, i.key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signed)
	authority := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.certificate.Raw})
	return proto.Marshal(&agentv1.IssuedCertificate{
		CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed}),
		ChainPem:       authority,
		TrustBundlePem: slices.Concat(authority, i.published),
		Identity: &agentv1.Identity{
			Subject:           certificate.Subject.CommonName,
			Serial:            hex.EncodeToString(certificate.SerialNumber.Bytes()),
			FingerprintSha256: hex.EncodeToString(digest[:]),
			IssuedAt:          timestamppb.New(certificate.NotBefore),
			ExpiresAt:         timestamppb.New(certificate.NotAfter),
		},
	})
}

func (i *issuing) renewing(t *testing.T, refused string, status int) *served {
	t.Helper()
	listener := &served{}
	return i.serving(t, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listener.served.Add(1)
		answer := func(status int, body []byte) {
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.WriteHeader(status)
			w.Write(body)
		}
		refusal := func(status int, code string) {
			encoded, _ := proto.Marshal(&controlv1.Refusal{Code: code, Detail: "refused by the test platform"})
			answer(status, encoded)
		}
		if r.URL.Path != "/v1/agents/certificate" || len(r.TLS.VerifiedChains) == 0 {
			refusal(http.StatusNotFound, "not_found")
			return
		}
		if refused != "" {
			refusal(status, refused)
			return
		}
		content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
		var asked agentv1.RenewalRequest
		if err == nil {
			err = proto.Unmarshal(content, &asked)
		}
		var issued []byte
		if err == nil {
			issued, err = i.issued(asked.GetCsrPem(), r.TLS.VerifiedChains[0][0].Subject.CommonName, nil)
		}
		if err != nil {
			refusal(http.StatusUnprocessableEntity, "malformed_certificate_request")
			return
		}
		answer(http.StatusCreated, issued)
	}))
}

func saved(t *testing.T, issued []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "issued.pb")
	if err := os.WriteFile(path, issued, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// The spool of the installation in state, opened as the agent opens it and
// held with the installation until release, as a running agent holds both.
func spoolIn(t *testing.T, state string) (*spool.Spool, func()) {
	t.Helper()
	installation, err := identity.Open(state)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	settings := config.Config{
		Spool:     config.Spool{MaxBytes: 64 << 20, MaxAge: config.Duration(72 * time.Hour)},
		Transport: config.Transport{MaxBatchBytes: 4 << 20},
	}
	held, err := openSpool(installation, settings, slog.New(slog.DiscardHandler))
	if err != nil {
		installation.Close()
		t.Fatalf("open the spool: %v", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if err := errors.Join(held.Close(), installation.Close()); err != nil {
			t.Errorf("close the spool and the installation: %v", err)
		}
	}
	t.Cleanup(release)
	return held, release
}

func exposesKeys(t *testing.T, logs, state string) bool {
	t.Helper()
	held, err := filepath.Glob(filepath.Join(state, keysDirectory, "*.pem"))
	if err != nil {
		t.Fatalf("list the keys: %v", err)
	}
	for _, path := range held {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		block, _ := pem.Decode(content)
		if block == nil {
			continue
		}
		for _, line := range strings.Split(string(pem.EncodeToMemory(&pem.Block{Bytes: block.Bytes})), "\n") {
			if len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(logs, line) {
				return true
			}
		}
	}
	return false
}

func follow(t *testing.T, logs io.Reader) <-chan map[string]any {
	entries := make(chan map[string]any)
	go func() {
		defer close(entries)
		lines := bufio.NewScanner(logs)
		for lines.Scan() {
			entry := map[string]any{}
			if err := json.Unmarshal(lines.Bytes(), &entry); err != nil {
				entry = map[string]any{"msg": lines.Text()}
			}
			select {
			case entries <- entry:
			case <-t.Context().Done():
				return
			}
		}
	}()
	return entries
}

func await(t *testing.T, entries <-chan map[string]any, message string) map[string]any {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case entry, open := <-entries:
			if !open {
				t.Fatalf("the agent closed its log before %s", message)
			}
			if entry["msg"] == message {
				return entry
			}
		case <-timeout:
			t.Fatalf("the agent logged no %s within 10s", message)
		}
	}
}

func running(t *testing.T, path string) (<-chan map[string]any, func() (int, []map[string]any)) {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	exited := make(chan int, 1)
	go func() {
		exited <- serve(ctx, writer, path)
		writer.Close()
	}()
	entries := follow(t, reader)
	var once sync.Once
	code, rest := 0, []map[string]any(nil)
	stop := func() (int, []map[string]any) {
		once.Do(func() {
			cancel()
			for entry := range entries {
				rest = append(rest, entry)
			}
			code = <-exited
		})
		return code, rest
	}
	t.Cleanup(func() { stop() })
	return entries, stop
}

func stateDirectory(t *testing.T) string {
	return filepath.Join(t.TempDir(), "state")
}

func serveStopped(t *testing.T, path string) string {
	t.Helper()
	ctx, stop := context.WithCancel(t.Context())
	stop()
	var logs bytes.Buffer
	if code := serve(ctx, &logs, path); code != 0 {
		t.Fatalf("exit code %d:\n%s", code, logs.String())
	}
	return logs.String()
}

// The settings an operator writes: where the installation is, which platform
// the agent reaches, and whatever else the test says.
func configured(t *testing.T, state string, sections map[string]string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	authority(t, directory)
	path := filepath.Join(directory, "agent.json")
	rewrite(t, path, state, sections)
	return path
}

func rewrite(t *testing.T, path, state string, sections map[string]string) {
	t.Helper()
	held := map[string]string{
		"format":   "1",
		"identity": fmt.Sprintf(`{"state_directory": %q}`, state),
		"server": fmt.Sprintf(`{"ingest_url": "https://gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q}`,
			filepath.Join(filepath.Dir(path), "platform-ca.pem")),
	}
	maps.Copy(held, sections)
	var settings []string
	for _, name := range slices.Sorted(maps.Keys(held)) {
		settings = append(settings, fmt.Sprintf("%q: %s", name, held[name]))
	}
	if err := os.WriteFile(path, []byte("{"+strings.Join(settings, ", ")+"}\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func authority(t *testing.T, directory string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of the platform authority: %v", err)
	}
	platform := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull platform"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	signed, err := x509.CreateCertificate(rand.Reader, platform, platform, key.Public(), key)
	if err != nil {
		t.Fatalf("sign the certificate of the platform authority: %v", err)
	}
	path := filepath.Join(directory, "platform-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed}), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func logged(t *testing.T, logs, message string) (map[string]any, bool) {
	t.Helper()
	for line := range strings.Lines(logs) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			return entry, true
		}
	}
	return nil, false
}
