package assessment

import (
	"context"
	"os"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/kmod"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/logindefs"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/metadata"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sshd"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sysctl"
)

// Host is what the checks read of the machine the agent runs on, each through
// the platform adapter that owns its source.
type Host interface {
	Hostname() (string, error)
	Describe(path string) (metadata.Node, error)
	Accounts() (accounts.Database, error)
	Parameter(name string) (string, error)
	Modules() (Modules, error)
	Modprobe() (Modprobe, error)
	Packages(ctx context.Context) ([]dpkg.Package, error)
	Units(ctx context.Context, names []string) ([]services.Unit, error)
	SSHD() (Directives, error)
	LoginDefs() (map[string]logindefs.Setting, error)
}

type Modules interface {
	State(name string) (kmod.State, error)
}

type Modprobe interface {
	Install(name string) (kmod.Rule, bool)
	Blacklisted(name string) (kmod.Rule, bool)
}

type Directives interface {
	Settings(keyword string) []sshd.Setting
}

type system struct{}

func System() Host { return system{} }

func (system) Hostname() (string, error)                        { return os.Hostname() }
func (system) Describe(path string) (metadata.Node, error)      { return metadata.Describe(path) }
func (system) Accounts() (accounts.Database, error)             { return accounts.Read() }
func (system) Parameter(name string) (string, error)            { return sysctl.Read(name) }
func (system) Modules() (Modules, error)                        { return kmod.ReadKernel() }
func (system) Modprobe() (Modprobe, error)                      { return kmod.ReadConfiguration() }
func (system) SSHD() (Directives, error)                        { return sshd.Read() }
func (system) LoginDefs() (map[string]logindefs.Setting, error) { return logindefs.Read() }
func (system) Packages(ctx context.Context) ([]dpkg.Package, error) {
	return dpkg.Installed(ctx)
}
func (system) Units(ctx context.Context, names []string) ([]services.Unit, error) {
	return services.Show(ctx, names)
}
