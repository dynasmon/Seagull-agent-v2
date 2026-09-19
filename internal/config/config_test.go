package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
)

func TestTheSettingsTheFileLeavesOutAreTheOnesTheAgentDocuments(t *testing.T) {
	path := configured(t, nil)
	settings, err := config.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	want := config.Config{
		Format:   config.Format,
		Identity: config.Identity{StateDirectory: state(path), KeyProvider: "filesystem"},
		Server: config.Server{
			IngestURL:   "https://gateway.example:8443",
			RenewalURL:  "https://control.example:8446",
			TrustBundle: authority(path),
		},
		Transport: config.Transport{
			ConnectTimeout:   config.Duration(10 * time.Second),
			RequestTimeout:   config.Duration(30 * time.Second),
			MaxBatchBytes:    4 << 20,
			MaxResponseBytes: 64 << 10,
		},
		Spool:   config.Spool{MaxBytes: 512 << 20, MaxAge: config.Duration(72 * time.Hour)},
		Modules: config.Modules{},
		Resources: config.Resources{
			MemoryLimit:              256 << 20,
			MaxConcurrentCollections: 2,
			MaxConcurrentUploads:     1,
			ShutdownTimeout:          config.Duration(10 * time.Second),
		},
		Logging: config.Logging{Level: "info", Format: "json"},
		Updates: config.Updates{Enabled: false},
	}
	if !reflect.DeepEqual(settings, want) {
		t.Fatalf("the agent runs on\n%+v\nand the settings it leaves out are\n%+v", settings, want)
	}
	if settings.Logging.Severity() != slog.LevelInfo {
		t.Errorf("a configuration that logs at %q logs at %v", settings.Logging.Level, settings.Logging.Severity())
	}
}

func TestNoBudgetTheAgentStartsWithIsUnlimited(t *testing.T) {
	settings, err := config.Load(configured(t, nil))
	if err != nil {
		t.Fatalf("load the configuration: %v", err)
	}
	budgets(t, reflect.ValueOf(settings), "")
}

func budgets(t *testing.T, held reflect.Value, name string) {
	t.Helper()
	if held.Kind() == reflect.Struct {
		for index := range held.NumField() {
			budgets(t, held.Field(index), held.Type().Field(index).Tag.Get("json"))
		}
		return
	}
	switch held.Kind() {
	case reflect.Int, reflect.Int64:
		if held.Int() <= 0 {
			t.Errorf("%s is %v, and a budget the agent starts with is never unlimited", name, held.Interface())
		}
	}
}

func TestASettingThisAgentDoesNotHaveIsRefused(t *testing.T) {
	for name, sections := range map[string]map[string]string{
		"a setting of its own":      {"spool_max_bytes": `"512MiB"`},
		"a setting of a group":      {"spool": `{"max_bytes": "512MiB", "keep_forever": true}`},
		"a setting spelled wrongly": {"logging": `{"levl": "debug"}`},
		"a setting of a module":     {"modules": `{"auth": {"enable": true}}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(configured(t, sections))
			if !errors.Is(err, config.ErrInvalid) || !strings.Contains(err.Error(), "is not a setting this agent has") {
				t.Fatalf("the agent read a setting it does not have: %v", err)
			}
		})
	}
}

func TestASettingThatSaysTwoThingsAtOnceIsRefused(t *testing.T) {
	for name, content := range map[string]string{
		"a group written twice":   `{"format": 1, "spool": {"max_bytes": "64MiB"}, "spool": {"max_bytes": "128MiB"}}`,
		"a setting written twice": `{"format": 1, "spool": {"max_bytes": "64MiB", "max_bytes": "128MiB"}}`,
		"a setting left null":     `{"format": 1, "spool": {"max_bytes": null}}`,
		"a group left null":       `{"format": 1, "spool": null}`,
		"more than one document":  `{"format": 1} {"format": 1}`,
		"a list of settings":      `[{"format": 1}]`,
		"nothing at all":          ``,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(written(t, trusted(t), content))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("the agent read %s: %v", name, err)
			}
		})
	}
}

func TestASizeOrATimeWithoutItsUnitIsRefused(t *testing.T) {
	for name, sections := range map[string]map[string]string{
		"a size as a number":         {"spool": `{"max_bytes": 536870912}`},
		"a size in decimal units":    {"spool": `{"max_bytes": "512MB"}`},
		"a size with nothing behind": {"spool": `{"max_bytes": "512"}`},
		"a time as a number":         {"spool": `{"max_age": 72}`},
		"a time with nothing behind": {"transport": `{"request_timeout": "30"}`},
		"a time in days":             {"spool": `{"max_age": "3d"}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(configured(t, sections))
			if !errors.Is(err, config.ErrInvalid) || !strings.Contains(err.Error(), "and it takes a") {
				t.Fatalf("the agent read %s: %v", name, err)
			}
			for setting := range sections {
				if !strings.Contains(err.Error(), setting+".") {
					t.Errorf("the agent did not name the setting it refused: %v", err)
				}
			}
		})
	}
}

func TestASettingOutsideWhatTheAgentSpendsIsRefused(t *testing.T) {
	for name, sections := range map[string]map[string]string{
		"a spool smaller than a batch":  {"spool": `{"max_bytes": "16MiB"}`, "transport": `{"max_batch_bytes": "8MiB"}`},
		"a spool of no bytes":           {"spool": `{"max_bytes": "0B"}`},
		"a spool kept beyond a month":   {"spool": `{"max_age": "1000h"}`},
		"a batch above the gateway":     {"transport": `{"max_batch_bytes": "16MiB"}`},
		"a request shorter than a dial": {"transport": `{"connect_timeout": "30s", "request_timeout": "5s"}`},
		"memory below what it needs":    {"resources": `{"memory_limit": "8MiB"}`},
		"no upload at all":              {"resources": `{"max_concurrent_uploads": 0}`},
		"more collection than it has":   {"resources": `{"max_concurrent_collections": 1024}`},
		"a stop that never gives up":    {"resources": `{"shutdown_timeout": "1h"}`},
		"a level it does not log at":    {"logging": `{"level": "trace"}`},
		"a log it does not write":       {"logging": `{"format": "logfmt"}`},
		"a provider it does not have":   {"identity": `{"state_directory": "/var/lib/seagull-agent", "key_provider": "tpm"}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(configured(t, sections)); !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("the agent runs on %s: %v", name, err)
			}
		})
	}
}

func TestTheConfigurationNamesAPlatformTheAgentCanAuthenticate(t *testing.T) {
	for name, endpoint := range map[string]string{
		"an unencrypted listener":     "http://gateway.example:8443",
		"a listener with no host":     "https://",
		"a listener that is a path":   "/v1/events",
		"a listener carrying a token": "https://agent:secret@gateway.example:8443",
		"a listener with a question":  "https://gateway.example:8443/?tenant=acme",
		"a listener to resolve":       "https://gateway.example:8443/v1/../v1",
	} {
		t.Run(name, func(t *testing.T) {
			directory := trusted(t)
			refused := written(t, directory, fmt.Sprintf(
				`{"format": 1, "identity": {"state_directory": "/var/lib/seagull-agent"}, "server": {"ingest_url": %q, "renewal_url": "https://control.example:8446", "trust_bundle": %q}}`,
				endpoint, platform(t, directory)))
			_, err := config.Load(refused)
			if !errors.Is(err, config.ErrInvalid) || !strings.Contains(err.Error(), "server.ingest_url") {
				t.Fatalf("the agent would reach %s: %v", name, err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("the refusal repeats what the URL carried: %v", err)
			}
		})
	}
}

func TestTheAgentVerifiesThePlatformAgainstCertificatesItRead(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, directory string) string{
		"a bundle that is not there": func(t *testing.T, directory string) string {
			return filepath.Join(directory, "absent.pem")
		},
		"a bundle that holds no PEM": func(t *testing.T, directory string) string {
			return write(t, directory, "not-pem.pem", "a certificate, honestly")
		},
		"a bundle that holds a key": func(t *testing.T, directory string) string {
			return write(t, directory, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")})))
		},
		"a bundle that is not a file": func(t *testing.T, directory string) string {
			held := filepath.Join(directory, "bundle.d")
			if err := os.Mkdir(held, 0o700); err != nil {
				t.Fatalf("create %s: %v", held, err)
			}
			return held
		},
		"a bundle others can change": func(t *testing.T, directory string) string {
			bundle := platform(t, directory)
			if err := os.Chmod(bundle, 0o666); err != nil {
				t.Fatalf("expose %s: %v", bundle, err)
			}
			return bundle
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := trusted(t)
			refused := written(t, directory, fmt.Sprintf(
				`{"format": 1, "identity": {"state_directory": "/var/lib/seagull-agent"}, "server": {"ingest_url": "https://gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q}}`,
				prepare(t, directory)))
			if _, err := config.Load(refused); !errors.Is(err, config.ErrInvalid) || !strings.Contains(err.Error(), "server.trust_bundle") {
				t.Fatalf("the agent trusts %s: %v", name, err)
			}
		})
	}
}

func TestEverySettingTheFileGetsWrongIsReportedAtOnce(t *testing.T) {
	path := configured(t, map[string]string{
		"spool":     `{"max_bytes": "1MiB", "max_age": "1000h"}`,
		"logging":   `{"level": "trace", "format": "logfmt"}`,
		"resources": `{"max_concurrent_uploads": 0}`,
	})
	_, err := config.Load(path)
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("the agent ran on five settings it refuses: %v", err)
	}
	for _, refused := range []string{"spool.max_bytes", "spool.max_age", "logging.level", "logging.format", "resources.max_concurrent_uploads"} {
		if !strings.Contains(err.Error(), refused) {
			t.Errorf("the agent did not report %s:\n%v", refused, err)
		}
	}
	for range 3 {
		_, again := config.Load(path)
		if again.Error() != err.Error() {
			t.Fatalf("the same configuration was refused with\n%v\nand then with\n%v", err, again)
		}
	}
}

func TestAConfigurationAnotherAccountCanChangeIsRefused(t *testing.T) {
	for name, expose := range map[string]func(t *testing.T, path string){
		"a configuration others can write": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatalf("expose %s: %v", path, err)
			}
		},
		"a directory others can write": func(t *testing.T, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
				t.Fatalf("expose %s: %v", filepath.Dir(path), err)
			}
		},
		"a configuration its group can write": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o660); err != nil {
				t.Fatalf("expose %s: %v", path, err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := configured(t, nil)
			expose(t, path)
			if _, err := config.Load(path); !errors.Is(err, config.ErrInsecure) {
				t.Fatalf("the agent read %s: %v", name, err)
			}
		})
	}
}

func TestAConfigurationWrittenForAnotherReleaseIsRefusedRatherThanGuessed(t *testing.T) {
	for name, content := range map[string]struct {
		written string
		want    error
	}{
		"a newer format":     {written: `{"format": 2}`, want: config.ErrNewer},
		"a format that went": {written: `{"format": 0}`, want: config.ErrInvalid},
		"no format at all":   {written: `{"logging": {"level": "debug"}}`, want: config.ErrInvalid},
		"a format as text":   {written: `{"format": "1"}`, want: config.ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(written(t, trusted(t), content.written))
			if !errors.Is(err, content.want) {
				t.Fatalf("the agent read %s: %v", name, err)
			}
		})
	}
}

func TestThisBuildConfiguresNoCollectorAndInstallsNoUpdate(t *testing.T) {
	for name, sections := range map[string]map[string]string{
		"a collector it does not have": {"modules": `{"auth": {"enabled": true}}`},
		"an update it cannot install":  {"updates": `{"enabled": true}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(configured(t, sections)); !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("the agent promised %s: %v", name, err)
			}
		})
	}
	if _, err := config.Load(configured(t, map[string]string{"modules": `{}`, "updates": `{"enabled": false}`})); err != nil {
		t.Fatalf("an agent that collects nothing and updates itself never: %v", err)
	}
}

func TestThePrintedConfigurationIsTheOneTheAgentRunsOn(t *testing.T) {
	path := configured(t, map[string]string{"logging": `{"level": "debug"}`, "spool": `{"max_age": "90m"}`})
	settings, err := config.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	printed, err := settings.Encode()
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	for _, shown := range []string{`"format": 1`, `"level": "debug"`, `"max_age": "90m"`, `"memory_limit": "256MiB"`, `"modules": {}`} {
		if !strings.Contains(string(printed), shown) {
			t.Errorf("the printed configuration does not show %s:\n%s", shown, printed)
		}
	}
	held, err := os.ReadFile(authority(path))
	if err != nil {
		t.Fatalf("read the trust bundle: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(held)), "\n") {
		if len(line) > 16 && strings.Contains(string(printed), line) {
			t.Fatalf("the printed configuration holds what %s holds:\n%s", authority(path), printed)
		}
	}
	again, err := config.Load(written(t, trusted(t), string(printed)))
	if err != nil {
		t.Fatalf("the agent refused the configuration it printed: %v", err)
	}
	if !reflect.DeepEqual(again, settings) {
		t.Fatalf("the agent printed\n%+v\nand read it back as\n%+v", settings, again)
	}
}

// A setting names where a credential is kept; it never holds one, so the
// configuration stays something an operator can read, copy and send for help.
func TestNoSettingCarriesASecretOrTurnsVerificationOff(t *testing.T) {
	credentials := []string{"secret", "token", "password", "credential", "key"}
	refused := []string{"insecure", "skip", "unverified", "disable", "unsafe", "plaintext"}
	names(t, reflect.TypeFor[config.Config](), "", func(name string) {
		leaf := name[strings.LastIndex(name, ".")+1:]
		for _, word := range strings.Split(leaf, "_") {
			if slices.Contains(credentials, word) && !strings.HasSuffix(leaf, "_file") && !strings.HasSuffix(leaf, "_directory") && !strings.HasSuffix(leaf, "_provider") {
				t.Errorf("%s holds credential material, and a setting names where one is kept", name)
			}
			if slices.Contains(refused, word) {
				t.Errorf("%s weakens a check the agent always makes", name)
			}
		}
	})
}

func names(t *testing.T, held reflect.Type, path string, each func(string)) {
	t.Helper()
	switch held.Kind() {
	case reflect.Struct:
		for index := range held.NumField() {
			field := held.Field(index)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" {
				t.Fatalf("%s.%s is a setting with no name in the file", path, field.Name)
			}
			each(strings.TrimPrefix(path+"."+name, "."))
			names(t, field.Type, strings.TrimPrefix(path+"."+name, "."), each)
		}
	case reflect.Map, reflect.Slice:
		names(t, held.Elem(), path, each)
	}
}

func configured(t *testing.T, sections map[string]string) string {
	t.Helper()
	directory := trusted(t)
	held := map[string]string{
		"format":   "1",
		"identity": fmt.Sprintf(`{"state_directory": %q}`, filepath.Join(directory, "state")),
		"server": fmt.Sprintf(`{"ingest_url": "https://gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q}`,
			platform(t, directory)),
	}
	for name, value := range sections {
		held[name] = value
	}
	var settings []string
	for _, name := range slices.Sorted(maps.Keys(held)) {
		settings = append(settings, fmt.Sprintf("%q: %s", name, held[name]))
	}
	return written(t, directory, "{"+strings.Join(settings, ", ")+"}")
}

// The directory an operator keeps the agent's configuration in: everybody may
// read the settings, and only the account the agent runs as may write them.
func trusted(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("hold %s: %v", directory, err)
	}
	return directory
}

func state(path string) string { return filepath.Join(filepath.Dir(path), "state") }

func authority(path string) string { return filepath.Join(filepath.Dir(path), "platform-ca.pem") }

func written(t *testing.T, directory, content string) string {
	t.Helper()
	return write(t, directory, "agent.json", content)
}

func write(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func platform(t *testing.T, directory string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of the platform authority: %v", err)
	}
	authority := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull platform"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	signed, err := x509.CreateCertificate(rand.Reader, authority, authority, key.Public(), key)
	if err != nil {
		t.Fatalf("sign the certificate of the platform authority: %v", err)
	}
	return write(t, directory, "platform-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed})))
}
