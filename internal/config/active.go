package config

import (
	"errors"
	"fmt"
	"maps"
	"sync"
)

// Active is the configuration the agent runs on: the one it read as it
// started, until a reload replaces it whole, and the one it keeps whole when
// a reload is refused.
type Active struct {
	mu       sync.RWMutex
	settings Config
}

func Activate(settings Config) *Active { return &Active{settings: settings.clone()} }

func (a *Active) Settings() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.settings.clone()
}

func (a *Active) Reload(candidate Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.settings.settled(candidate); err != nil {
		return err
	}
	a.settings = candidate.clone()
	return nil
}

func (c Config) clone() Config {
	c.Modules = maps.Clone(c.Modules)
	return c
}

// What the agent opened, built or bounded itself with as it started. A reload
// that changes one of these is refused whole: applying the rest would leave an
// agent that is half the configuration it read and half the one it runs on.
func (c Config) settled(next Config) error {
	var found []error
	for _, fixed := range []struct{ name, before, after string }{
		{name: "identity.state_directory", before: c.Identity.StateDirectory, after: next.Identity.StateDirectory},
		{name: "identity.key_provider", before: c.Identity.KeyProvider, after: next.Identity.KeyProvider},
		{name: "logging.format", before: c.Logging.Format, after: next.Logging.Format},
		{name: "resources.shutdown_timeout", before: c.Resources.ShutdownTimeout.String(), after: next.Resources.ShutdownTimeout.String()},
	} {
		if fixed.before != fixed.after {
			found = append(found, fmt.Errorf("%s is %s and the file now says %s", fixed.name, fixed.before, fixed.after))
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("%w: %w", ErrFixed, errors.Join(found...))
	}
	return nil
}
