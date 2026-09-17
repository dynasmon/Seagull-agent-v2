package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"syscall"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
)

const (
	shutdownTimeout = 10 * time.Second
	keysDirectory   = "keys"
)

const usage = `Usage:
  seagull-agent -state DIR run                    run the agent until it receives SIGINT or SIGTERM
  seagull-agent -state DIR installation replace   replace the installation with a new one that is not enrolled
  seagull-agent -version                          print the build identity and the wire versions it speaks, and exit
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("seagull-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usage) }
	version := flags.Bool("version", false, "print the build identity and the wire versions it speaks, and exit")
	state := flags.String("state", "", "the directory that holds the installation state")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch {
	case *version && *state == "" && flags.NArg() == 0:
		fmt.Fprintln(stdout, buildIdentity())
		for _, spoken := range wireVersions() {
			fmt.Fprintf(stdout, "%s %d\n", spoken.name, spoken.version)
		}
		return 0
	case !*version && *state != "" && slices.Equal(flags.Args(), []string{"run"}):
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, slog.New(slog.NewJSONHandler(stderr, nil)), *state)
	case !*version && *state != "" && slices.Equal(flags.Args(), []string{"installation", "replace"}):
		return replace(*state, stdout, stderr)
	}
	flags.Usage()
	return 2
}

func serve(ctx context.Context, logger *slog.Logger, state string, components ...agentruntime.Component) int {
	agent, err := agentruntime.New(logger, shutdownTimeout, components...)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err))
		return 1
	}
	installation, err := identity.Open(state)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(state, err)))
		return 1
	}
	defer installation.Close()
	if installation.Created() {
		logger.Info("installation_created", slog.String("installation_id", installation.ID()), slog.String("state", state))
	}
	keys, err := openKeys(installation)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(state, err)))
		return 1
	}
	started := []any{slog.String("build", buildIdentity())}
	for _, spoken := range wireVersions() {
		started = append(started, slog.Int(spoken.name, spoken.version))
	}
	started = append(started, slog.String("installation_id", installation.ID()))
	if enrolled, ok := installation.Enrollment(); ok {
		if _, err := keys.Open(enrolled.KeyID); err != nil {
			logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(state, err)))
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

func openKeys(installation *identity.Installation) (pki.KeyProvider, error) {
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

func replace(state string, stdout, stderr io.Writer) int {
	installation, err := identity.Replace(state)
	if err != nil {
		fmt.Fprintf(stderr, "seagull-agent: %v\n", err)
		fmt.Fprintf(stderr, "seagull-agent: %s\n", recovery(state, err))
		return 1
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

// What an operator does next depends on why the installation cannot be used,
// and never on the agent deciding it for them: a damaged or newer state is
// replaced only when somebody asks for it.
func recovery(state string, err error) string {
	replacement := fmt.Sprintf(`"seagull-agent -state %s installation replace"`, state)
	switch {
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
	}
	return "check that " + state + " can be created and read by the account the agent runs as"
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
