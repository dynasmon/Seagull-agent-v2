package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
)

const keysDirectory = "keys"

const usage = `Usage:
  seagull-agent -config FILE run                    run the agent until it receives SIGINT or SIGTERM
  seagull-agent -config FILE config check           read the configuration, report what it refuses, and exit
  seagull-agent -config FILE config print           print the configuration the agent would run on, and exit
  seagull-agent -config FILE installation replace   replace the installation with a new one that is not enrolled
  seagull-agent -version                            print the build identity and the wire versions it speaks, and exit

A running agent reads its configuration again when it receives SIGHUP, and
keeps the one it has when it refuses the file.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("seagull-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usage) }
	version := flags.Bool("version", false, "print the build identity and the wire versions it speaks, and exit")
	path := flags.String("config", "", "the file that holds the agent's configuration")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	configured := !*version && *path != ""
	switch {
	case *version && *path == "" && flags.NArg() == 0:
		fmt.Fprintln(stdout, buildIdentity())
		for _, spoken := range wireVersions() {
			fmt.Fprintf(stdout, "%s %d\n", spoken.name, spoken.version)
		}
		return 0
	case configured && slices.Equal(flags.Args(), []string{"run"}):
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, stderr, *path)
	case configured && slices.Equal(flags.Args(), []string{"config", "check"}):
		return check(*path, stdout, stderr)
	case configured && slices.Equal(flags.Args(), []string{"config", "print"}):
		return show(*path, stdout, stderr)
	case configured && slices.Equal(flags.Args(), []string{"installation", "replace"}):
		return replace(*path, stdout, stderr)
	}
	flags.Usage()
	return 2
}

func serve(ctx context.Context, stderr io.Writer, path string, components ...agentruntime.Component) int {
	settings, err := config.Load(path)
	if err != nil {
		slog.New(slog.NewJSONHandler(stderr, nil)).Error("agent_not_started",
			slog.Any("error", err), slog.String("recovery", recovery(path, "", err)))
		return 1
	}
	level := new(slog.LevelVar)
	logger := logging(stderr, settings, level)
	apply(settings, level)
	state := settings.Identity.StateDirectory
	held := configuration{logger: logger, path: path, active: config.Activate(settings), level: level}

	asked := make(chan os.Signal, 1)
	signal.Notify(asked, syscall.SIGHUP)
	defer signal.Stop(asked)
	agent, err := agentruntime.New(logger, time.Duration(settings.Resources.ShutdownTimeout),
		append([]agentruntime.Component{held.component(asked)}, components...)...)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err))
		return 1
	}
	installation, err := identity.Open(state)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
		return 1
	}
	defer installation.Close()
	if installation.Created() {
		logger.Info("installation_created", slog.String("installation_id", installation.ID()), slog.String("state", state))
	}
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
		return 1
	}
	started := []any{slog.String("build", buildIdentity()), slog.String("config", path)}
	for _, spoken := range wireVersions() {
		started = append(started, slog.Int(spoken.name, spoken.version))
	}
	started = append(started, slog.String("installation_id", installation.ID()))
	if enrolled, ok := installation.Enrollment(); ok {
		if _, err := keys.Open(enrolled.KeyID); err != nil {
			logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
			return 1
		}
		started = append(started, slog.String("agent_id", enrolled.AgentID), slog.Uint64("credential_generation", enrolled.Generation))
	}
	posture := keys.Posture()
	started = append(started, slog.String("key_provider", posture.Provider), slog.Bool("key_exportable", posture.Exportable))
	logger.Info("agent_starting", started...)
	if err := agent.Run(ctx); err != nil {
		logger.Error("agent_stopped", slog.Any("error", err))
		return 1
	}
	logger.Info("agent_stopped")
	return 0
}

func logging(stderr io.Writer, settings config.Config, level *slog.LevelVar) *slog.Logger {
	options := &slog.HandlerOptions{Level: level}
	if settings.Logging.Format == config.TextLogs {
		return slog.New(slog.NewTextHandler(stderr, options))
	}
	return slog.New(slog.NewJSONHandler(stderr, options))
}

// What the agent spends on itself. The memory limit is a target the garbage
// collector works to, not a ceiling the kernel enforces: that one belongs to
// the service the agent is installed as.
func apply(settings config.Config, level *slog.LevelVar) {
	level.Set(settings.Logging.Severity())
	debug.SetMemoryLimit(int64(settings.Resources.MemoryLimit))
}

// The configuration the agent holds: the one it read as it started, and what
// it does when an operator asks it to read the file again. The agent keeps the
// one it holds whenever it refuses the file.
type configuration struct {
	logger *slog.Logger
	path   string
	active *config.Active
	level  *slog.LevelVar
}

func (c configuration) component(asked <-chan os.Signal) agentruntime.Component {
	return agentruntime.Component{
		Name:   "configuration",
		Policy: agentruntime.Essential,
		Run: func(ctx context.Context) error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-asked:
					c.reload()
				}
			}
		},
	}
}

func (c configuration) reload() {
	candidate, err := config.Load(c.path)
	if err == nil {
		err = c.active.Reload(candidate)
	}
	if err != nil {
		c.logger.Error("configuration_not_reloaded", slog.Any("error", err),
			slog.String("running_on", "the configuration the agent read before"),
			slog.String("recovery", recovery(c.path, "", err)))
		return
	}
	apply(candidate, c.level)
	c.logger.Info("configuration_reloaded", slog.String("config", c.path), slog.String("log_level", candidate.Logging.Level))
}

func openKeys(installation *identity.Installation, provider string) (pki.KeyProvider, error) {
	if provider != config.KeysInFiles {
		return nil, fmt.Errorf("this build keeps no key with %q", provider)
	}
	directory, err := installation.Directory(keysDirectory)
	if err != nil {
		return nil, err
	}
	keys, err := pki.OpenKeyFiles(directory)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func check(path string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	fmt.Fprintf(stdout, "%s is a configuration this agent runs on, as installation %s\n", path, settings.Identity.StateDirectory)
	return 0
}

func show(path string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	printed, err := settings.Encode()
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	if _, err := stdout.Write(printed); err != nil {
		return refuse(path, "", err, stderr)
	}
	return 0
}

func replace(path string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Replace(state)
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	defer installation.Close()
	fmt.Fprintf(stdout, "installation_id %s\n", installation.ID())
	if replaced := installation.Replaces(); replaced != "" {
		fmt.Fprintf(stdout, "replaces %s\n", replaced)
	}
	fmt.Fprintf(stderr, "seagull-agent: everything the replaced installation held, its keys included, is kept under %s; enroll the new installation before it delivers anything\n",
		filepath.Join(state, "replaced"))
	return 0
}

// Every setting the agent refuses is a line of its own, and the last line is
// what an operator does about them.
func refuse(path, state string, err error, stderr io.Writer) int {
	for line := range strings.SplitSeq(err.Error(), "\n") {
		fmt.Fprintf(stderr, "seagull-agent: %s\n", line)
	}
	fmt.Fprintf(stderr, "seagull-agent: %s\n", recovery(path, state, err))
	return 1
}

// What an operator does next depends on why the agent cannot run, and never on
// the agent deciding it for them: a damaged or newer state is replaced only
// when somebody asks for it.
func recovery(path, state string, err error) string {
	replacement := fmt.Sprintf(`"seagull-agent -config %s installation replace"`, path)
	reading := fmt.Sprintf(`"seagull-agent -config %s config check"`, path)
	switch {
	case errors.Is(err, config.ErrInvalid):
		return "correct " + path + ", which " + reading + " reads without starting the agent"
	case errors.Is(err, config.ErrNewer):
		return "run the agent release that wrote " + path + ", or write it in the format this release reads"
	case errors.Is(err, config.ErrInsecure):
		return "let the account the agent runs as, and root, change " + path + " and the directory that holds it, and nobody else"
	case errors.Is(err, config.ErrFixed):
		return "stop the agent and start it again for what it settles as it starts to change"
	case errors.Is(err, identity.ErrLocked):
		return "stop the agent that holds " + state + ": two agents never share an installation"
	case errors.Is(err, identity.ErrInsecure):
		return "make " + state + " and everything in it belong to the account the agent runs as, closed to its group and to others"
	case errors.Is(err, pki.ErrKeyInsecure):
		return "make " + state + " and everything in it belong to the account the agent runs as, closed to its group and to others; " +
			"if another account could read the key, revoke the certificate issued for it and discard the installation with " + replacement
	case errors.Is(err, identity.ErrNewer):
		return "run the agent release that wrote this state, or discard the installation with " + replacement
	case errors.Is(err, identity.ErrDamaged), errors.Is(err, pki.ErrKeyMissing), errors.Is(err, pki.ErrKeyDamaged):
		return "restore " + state + " from a backup of this installation, or discard the installation with " + replacement + " and enroll the new one"
	case errors.Is(err, identity.ErrNoInstallation):
		return "run the agent to create an installation"
	case errors.Is(err, fs.ErrNotExist):
		return "write the agent's configuration at " + path
	}
	return "check that " + path + " can be read by the account the agent runs as"
}

func buildIdentity() string {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	return fmt.Sprintf("seagull-agent %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

type wireVersion struct {
	name    string
	version int
}

func wireVersions() []wireVersion {
	return []wireVersion{
		{name: "protocol_version", version: protocol.Version},
		{name: "event_schema_version", version: protocol.EventSchemaVersion},
		{name: "inventory_schema_version", version: protocol.InventorySchemaVersion},
	}
}
