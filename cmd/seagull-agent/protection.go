package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

var guarded = protection

// What decides what the agent is and what it does: its executable, its
// configuration, the authorities it trusts, the keys it accepts a policy
// under, the root it verifies a release under, and the directory its
// installation is kept in. The agent runs only
// when root alone can change them, so whoever takes over its account, or any
// other but root, cannot change what it runs after it starts again.
func protection(path string, settings config.Config) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: find the agent's executable: %w", files.ErrUnprotected, err)
	}
	held := []struct{ what, path string }{
		{"the agent's executable", executable},
		{"the configuration", path},
		{"server.trust_bundle", settings.Server.TrustBundle},
		{"the directory that holds the installation", filepath.Dir(settings.Identity.StateDirectory)},
	}
	if settings.Policy.Signers != "" {
		held = append(held, struct{ what, path string }{"policy.signers", settings.Policy.Signers})
	}
	if settings.Updates.Root != "" {
		held = append(held, struct{ what, path string }{"updates.root", settings.Updates.Root})
	}
	for _, decides := range held {
		absolute, err := filepath.Abs(decides.path)
		if err == nil {
			err = files.Protected(absolute)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", decides.what, err)
		}
	}
	return nil
}
