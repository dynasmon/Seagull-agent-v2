package policy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

func local(t testing.TB, sections string) config.Config {
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
		"server": {"ingest_url": "https://gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q}%s}`,
		filepath.Join(directory, "state"), bundle, sections)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := config.Load(path)
	if err != nil {
		t.Fatalf("load the agent's own configuration: %v", err)
	}
	return settings
}

func TestAPolicyChangesWhatItSetsAndLeavesTheRestToTheAgentsOwn(t *testing.T) {
	own := local(t, `, "modules": {"authentication": {"enabled": true}, "inventory": {"enabled": true, "interval": "2h"}}`)
	before := own
	before.Modules = map[string]config.Module{}
	for name, module := range own.Modules {
		before.Modules[name] = module
	}

	made, kept, err := policy.Overlay(own, &policyv1.Settings{
		LogLevel: policyv1.LogLevel_LOG_LEVEL_DEBUG,
		Modules: []*policyv1.ModuleSettings{
			{Module: policyv1.Module_MODULE_AUTHENTICATION, Collection: policyv1.Collection_COLLECTION_DISABLED},
			{Module: policyv1.Module_MODULE_INVENTORY, Interval: durationpb.New(6 * time.Hour)},
			{Module: policyv1.Module_MODULE_FILES, Collection: policyv1.Collection_COLLECTION_ENABLED,
				Paths: &policyv1.Paths{Paths: []string{"/etc", "/usr/bin"}}, Exclude: &policyv1.Paths{Paths: []string{"*.swp"}}},
		},
		Budgets: &policyv1.Budgets{
			SpoolMaxBytes:        128 << 20,
			SpoolMaxAge:          durationpb.New(24 * time.Hour),
			MemoryLimitBytes:     1 << 30,
			MaxConcurrentScans:   1,
			MaxConcurrentUploads: 4,
		},
	})
	if err != nil {
		t.Fatalf("a policy within every bound was refused: %v", err)
	}
	switch {
	case made.Logging.Level != "debug" || made.Logging.Format != own.Logging.Format:
		t.Fatalf("the agent logs as %+v", made.Logging)
	case made.Modules["authentication"].Enabled:
		t.Fatal("the policy did not stop the authentication module")
	case !made.Modules["inventory"].Enabled || made.Modules["inventory"].Interval != config.Duration(6*time.Hour):
		t.Fatalf("the inventory module runs as %+v", made.Modules["inventory"])
	case !made.Modules["files"].Enabled || !slices.Equal(made.Modules["files"].Paths, []string{"/etc", "/usr/bin"}) ||
		!slices.Equal(made.Modules["files"].Exclude, []string{"*.swp"}) || made.Modules["files"].Interval != config.Duration(time.Hour):
		t.Fatalf("the files module runs as %+v", made.Modules["files"])
	case made.Spool.MaxBytes != 128<<20 || made.Spool.MaxAge != config.Duration(24*time.Hour) || made.Resources.MaxConcurrentScans != 1:
		t.Fatalf("the policy did not lower what it lowers: %+v %+v", made.Spool, made.Resources)
	case made.Resources.MemoryLimit != own.Resources.MemoryLimit || made.Resources.MaxConcurrentUploads != own.Resources.MaxConcurrentUploads:
		t.Fatalf("the policy raised a ceiling: %+v", made.Resources)
	case made.Server != own.Server || made.Identity != own.Identity || made.Transport.RequestTimeout != own.Transport.RequestTimeout:
		t.Fatal("the policy reached what no policy reaches")
	}
	want := []policy.Kept{
		{Setting: "resources.memory_limit", Own: "256MiB", Asked: fmt.Sprint(1<<30) + "B"},
		{Setting: "resources.max_concurrent_uploads", Own: "1", Asked: "4"},
	}
	if !reflect.DeepEqual(kept, want) {
		t.Fatalf("the ceilings the agent kept are reported as %+v", kept)
	}
	if !reflect.DeepEqual(own, before) {
		t.Fatal("laying a policy over the agent's configuration changed it")
	}

	assessing, _, err := policy.Overlay(own, &policyv1.Settings{
		Modules: []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_ASSESSMENT, Collection: policyv1.Collection_COLLECTION_ENABLED, Interval: durationpb.New(15 * time.Minute)}},
		Assessment: &assessmentv1.Checklist{Checks: []*assessmentv1.Check{{CheckId: "telnetd", Test: &assessmentv1.Check_Package{Package: &assessmentv1.PackageTest{
			Name: "telnetd", Presence: assessmentv1.Presence_PRESENCE_FORBIDDEN,
		}}}}},
	})
	if err != nil || !assessing.Modules["assessment"].Enabled || assessing.Modules["assessment"].Interval != config.Duration(15*time.Minute) {
		t.Fatalf("a policy enabling the assessment made %+v: %v", assessing.Modules["assessment"], err)
	}

	same, kept, err := policy.Overlay(own, &policyv1.Settings{})
	if err != nil || len(kept) != 0 || !reflect.DeepEqual(same, own) {
		t.Fatalf("a policy setting nothing made %+v, %v, %v", same, kept, err)
	}
}

func TestAPolicyTheAgentWouldNotRunOnChangesNothing(t *testing.T) {
	own := local(t, `, "transport": {"max_batch_bytes": "8MiB", "request_timeout": "30s", "max_upload_bytes_per_second": "1MiB"}`)
	for name, refused := range map[string]struct {
		settings *policyv1.Settings
		want     error
		says     string
	}{
		"a module this build does not have": {
			settings: &policyv1.Settings{Modules: []*policyv1.ModuleSettings{{Module: 77, Collection: policyv1.Collection_COLLECTION_ENABLED}}},
			want:     policy.ErrInapplicable, says: "does not have",
		},
		"a module named twice": {
			settings: &policyv1.Settings{Modules: []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_NETWORK}, {Module: policyv1.Module_MODULE_NETWORK}}},
			want:     policy.ErrMalformed, says: "twice",
		},
		"an interval outside the module's bounds": {
			settings: &policyv1.Settings{Modules: []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_NETWORK, Interval: durationpb.New(2 * time.Hour)}}},
			want:     policy.ErrInapplicable, says: "modules.network.interval",
		},
		"paths for a module that watches none": {
			settings: &policyv1.Settings{Modules: []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_INVENTORY, Paths: &policyv1.Paths{Paths: []string{"/etc"}}}}},
			want:     policy.ErrInapplicable, says: "only the files collector",
		},
		"a path the kernel makes up": {
			settings: &policyv1.Settings{Modules: []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_FILES, Paths: &policyv1.Paths{Paths: []string{"/proc"}}}}},
			want:     policy.ErrInapplicable, says: "within /proc",
		},
		"a spool that holds no four batches": {
			settings: &policyv1.Settings{Budgets: &policyv1.Budgets{SpoolMaxBytes: 16 << 20}},
			want:     policy.ErrInapplicable, says: "spool.max_bytes",
		},
		"an upload too slow for the request timeout": {
			settings: &policyv1.Settings{Budgets: &policyv1.Budgets{MaxUploadBytesPerSecond: 64 << 10}},
			want:     policy.ErrInapplicable, says: "transport.request_timeout",
		},
		"a memory below what the agent takes": {
			settings: &policyv1.Settings{Budgets: &policyv1.Budgets{MemoryLimitBytes: 1 << 20}},
			want:     policy.ErrInapplicable, says: "resources.memory_limit",
		},
		"a level the contract does not name": {
			settings: &policyv1.Settings{LogLevel: 9},
			want:     policy.ErrMalformed, says: "log_level",
		},
		"a checklist naming no check": {
			settings: &policyv1.Settings{Assessment: &assessmentv1.Checklist{}},
			want:     policy.ErrMalformed, says: "names 0 checks",
		},
		"a check named twice": {
			settings: &policyv1.Settings{Assessment: &assessmentv1.Checklist{Checks: []*assessmentv1.Check{{CheckId: "telnetd"}, {CheckId: "telnetd"}}}},
			want:     policy.ErrMalformed, says: "names check telnetd twice",
		},
		"a check named by no identifier": {
			settings: &policyv1.Settings{Assessment: &assessmentv1.Checklist{Checks: []*assessmentv1.Check{{CheckId: "telnet d"}}}},
			want:     policy.ErrMalformed, says: "checks[0].check_id",
		},
		"an interval outside the assessment's bounds": {
			settings: &policyv1.Settings{Modules: []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_ASSESSMENT, Interval: durationpb.New(48 * time.Hour)}}},
			want:     policy.ErrInapplicable, says: "modules.assessment.interval",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := policy.Overlay(own, refused.settings); !errors.Is(err, refused.want) || !strings.Contains(err.Error(), refused.says) {
				t.Fatalf("the policy was answered %v", err)
			}
		})
	}
}
