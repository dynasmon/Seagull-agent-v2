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
	"runtime"
	"runtime/debug"
	"slices"
	"syscall"
	"time"

	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
)

const shutdownTimeout = 10 * time.Second

const usage = `Usage:
  seagull-agent run        run the agent until it receives SIGINT or SIGTERM
  seagull-agent -version   print the build identity and exit
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("seagull-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usage) }
	version := flags.Bool("version", false, "print the build identity and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch {
	case *version && flags.NArg() == 0:
		fmt.Fprintln(stdout, buildIdentity())
		return 0
	case !*version && slices.Equal(flags.Args(), []string{"run"}):
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, slog.New(slog.NewJSONHandler(stderr, nil)))
	}
	flags.Usage()
	return 2
}

func serve(ctx context.Context, logger *slog.Logger, components ...agentruntime.Component) int {
	agent, err := agentruntime.New(logger, shutdownTimeout, components...)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err))
		return 1
	}
	logger.Info("agent_starting", slog.String("build", buildIdentity()))
	if err := agent.Run(ctx); err != nil {
		logger.Error("agent_stopped", slog.Any("error", err))
		return 1
	}
	logger.Info("agent_stopped")
	return 0
}

func buildIdentity() string {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	return fmt.Sprintf("seagull-agent %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
