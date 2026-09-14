package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("seagull-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "print the build identity and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "seagull-agent: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if !*version {
		flags.Usage()
		return 2
	}
	fmt.Fprintln(stdout, buildIdentity())
	return 0
}

func buildIdentity() string {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	return fmt.Sprintf("seagull-agent %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
