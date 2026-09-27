package config_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
)

func TestAReloadReplacesTheConfigurationWhole(t *testing.T) {
	started := load(t, configured(t, nil))
	active := config.Activate(started)
	asked := load(t, configured(t, map[string]string{
		"logging":   `{"level": "debug"}`,
		"spool":     `{"max_bytes": "1GiB", "max_age": "12h"}`,
		"resources": `{"memory_limit": "512MiB"}`,
	}))
	asked.Identity, asked.Server = started.Identity, started.Server

	if err := active.Reload(asked); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if running := active.Settings(); !reflect.DeepEqual(running, asked) {
		t.Fatalf("the agent runs on\n%+v\nand it was asked for\n%+v", running, asked)
	}
}

func TestAReloadThatChangesWhatTheAgentSettledAsItStartedIsRefused(t *testing.T) {
	started := load(t, configured(t, nil))
	for name, change := range map[string]func(settings *config.Config){
		"the installation it holds": func(settings *config.Config) {
			settings.Identity.StateDirectory = "/var/lib/seagull-agent-elsewhere"
		},
		"what holds its keys": func(settings *config.Config) { settings.Identity.KeyProvider = "tpm" },
		"where it delivers":   func(settings *config.Config) { settings.Server.IngestURL = "https://gateway.example:9443" },
		"where it renews":     func(settings *config.Config) { settings.Server.RenewalURL = "https://control.example:9446" },
		"how long it connects": func(settings *config.Config) {
			settings.Transport.ConnectTimeout = config.Duration(20 * time.Second)
		},
		"how long a request takes": func(settings *config.Config) {
			settings.Transport.RequestTimeout = config.Duration(time.Minute)
		},
		"how much of an answer it reads": func(settings *config.Config) { settings.Transport.MaxResponseBytes = 128 << 10 },
		"whom it trusts":                 func(settings *config.Config) { settings.Server.TrustBundle = "/etc/seagull-agent/other-ca.pem" },
		"the log it writes":              func(settings *config.Config) { settings.Logging.Format = "text" },
		"how long it stops":              func(settings *config.Config) { settings.Resources.ShutdownTimeout = config.Duration(0) },
	} {
		t.Run(name, func(t *testing.T) {
			active := config.Activate(started)
			asked := started
			asked.Logging.Level = "debug"
			change(&asked)

			err := active.Reload(asked)
			if !errors.Is(err, config.ErrFixed) {
				t.Fatalf("the agent changed %s while it ran: %v", name, err)
			}
			if running := active.Settings(); !reflect.DeepEqual(running, started) {
				t.Fatalf("a refused reload left the agent on\n%+v\nrather than\n%+v", running, started)
			}
			if strings.Count(err.Error(), "\n") != 0 {
				t.Errorf("the refusal reports more than the one setting that changed: %v", err)
			}
		})
	}
}

func TestTheSettingsAReaderHoldsAreItsOwn(t *testing.T) {
	settings := load(t, configured(t, nil))
	active := config.Activate(settings)
	held := active.Settings()
	held.Modules["auth"] = config.Module{Enabled: true}
	held.Spool.MaxBytes = 1
	if running := active.Settings(); len(running.Modules) != 0 || running.Spool.MaxBytes == 1 {
		t.Fatalf("a reader changed the configuration the agent runs on: %+v", running)
	}
}

func TestTheConfigurationIsReadWhileItIsReplaced(t *testing.T) {
	started := load(t, configured(t, nil))
	active := config.Activate(started)
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 200 {
				if settings := active.Settings(); settings.Identity.StateDirectory != started.Identity.StateDirectory {
					panic(fmt.Sprintf("a reader saw %q", settings.Identity.StateDirectory))
				}
			}
		}()
	}
	for level := range 200 {
		asked := started
		asked.Logging.Level = []string{"debug", "info", "warn", "error"}[level%4]
		if err := active.Reload(asked); err != nil {
			t.Fatalf("reload: %v", err)
		}
	}
	readers.Wait()
}

func load(t *testing.T, path string) config.Config {
	t.Helper()
	settings, err := config.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return settings
}
