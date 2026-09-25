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
	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/ceilings"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dumps"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/privileges"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

const (
	keysDirectory         = "keys"
	certificatesDirectory = "certificates"
	spoolDirectory        = "spool"
)

const usage = `Usage:
  seagull-agent -config FILE run                          run the agent until it receives SIGINT or SIGTERM
  seagull-agent -config FILE config check                 read the configuration, report what it refuses, and exit
  seagull-agent -config FILE config print                 print the configuration the agent would run on, and exit
  seagull-agent -config FILE platform check               authenticate the platform the configuration names, presenting and sending nothing, and exit
  seagull-agent -config FILE enrollment request AGENT_ID  ask for a certificate as AGENT_ID, printing the request the platform issues it from
  seagull-agent -config FILE enrollment import ISSUED     activate the certificate the platform answered the request with, held in ISSUED
  seagull-agent -config FILE installation replace         replace the installation with a new one that is not enrolled
  seagull-agent -version                                  print the build identity and the wire versions it speaks, and exit

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
	case configured && slices.Equal(flags.Args(), []string{"platform", "check"}):
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return reach(ctx, *path, stdout, stderr)
	case configured && flags.NArg() == 3 && flags.Arg(0) == "enrollment" && flags.Arg(1) == "request":
		return ask(*path, flags.Arg(2), stdout, stderr)
	case configured && flags.NArg() == 3 && flags.Arg(0) == "enrollment" && flags.Arg(1) == "import":
		return accept(*path, flags.Arg(2), stdout, stderr)
	case configured && slices.Equal(flags.Args(), []string{"installation", "replace"}):
		return replace(*path, stdout, stderr)
	}
	flags.Usage()
	return 2
}

func serve(ctx context.Context, stderr io.Writer, path string, components ...agentruntime.Component) int {
	withheld := dumps.Withhold()
	granted, err := privileges.Held()
	if err != nil {
		return unstarted(stderr, path, err)
	}
	settings, err := config.Load(path)
	if err != nil {
		return unstarted(stderr, path, err)
	}
	level := new(slog.LevelVar)
	logger := logging(stderr, settings, level)
	apply(settings, level)
	inventory(logger, granted)
	memory(logger, withheld)
	resources(logger, settings)
	state := settings.Identity.StateDirectory
	held := &configuration{logger: logger, path: path, active: config.Activate(settings), level: level}

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
	certificates, err := openCertificates(installation)
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
		if _, err := (credentials{installation: installation, keys: keys, certificates: certificates}).Credential(); err != nil {
			logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
			return 1
		}
		started = append(started, slog.String("agent_id", enrolled.AgentID), slog.Uint64("credential_generation", enrolled.Generation))
	}
	posture := keys.Posture()
	started = append(started, slog.String("key_provider", posture.Provider), slog.Bool("key_exportable", posture.Exportable))
	spooled, err := openSpool(installation, settings, logger)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
		return 1
	}
	defer spooled.Close()
	held.spool = spooled
	backlog(logger, spooled.Stats())
	governed, err := governor.New(logger, installation.ID(), budget(settings))
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
		return 1
	}
	held.governor = governed
	logger.Info("agent_starting", started...)
	if err := agent.Run(ctx); err != nil {
		logger.Error("agent_stopped", slog.Any("error", err))
		return 1
	}
	logger.Info("agent_stopped")
	return 0
}

func unstarted(stderr io.Writer, path string, err error) int {
	slog.New(slog.NewJSONHandler(stderr, nil)).Error("agent_not_started",
		slog.Any("error", err), slog.String("recovery", recovery(path, "", err)))
	return 1
}

// What the agent needs of the machine beyond the account it runs as: nothing.
// Its installation, its keys and its settings are files that account reaches,
// and the platform is a network service like any other. A collector that needs
// more names it here, and every module shares whatever the process holds.
func needed() []string { return nil }

func inventory(logger *slog.Logger, granted privileges.Privileges) {
	reported := []any{
		slog.Int("user", granted.User),
		slog.Int("group", granted.Group),
		slog.Any("groups", granted.Groups),
		slog.Any("capabilities", granted.Capabilities),
		slog.Bool("no_new_privs", granted.NoNewPrivs),
	}
	beyond := granted.Beyond(needed())
	if len(beyond) == 0 {
		logger.Info("agent_privileges", reported...)
		return
	}
	logger.Warn("agent_privileges", append(reported, slog.Any("beyond", beyond),
		slog.String("recovery", "run the agent as an account of its own, in the groups the files it reads belong to: nothing this build does needs more"))...)
}

// What the kernel would hand whoever asks of what the agent holds in memory.
// Its key lives there, and a core dump is a copy of that key in a file the
// agent neither writes nor protects, so it starts by asking for neither.
func memory(logger *slog.Logger, withheld error) {
	if withheld != nil {
		logger.Warn("agent_core_dumps", slog.Bool("withheld", false), slog.Any("error", withheld),
			slog.String("recovery", "let the service that starts the agent leave the kernel nothing to write, with LimitCORE=0 or what the platform calls it"))
		return
	}
	logger.Info("agent_core_dumps", slog.Bool("withheld", true))
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
	logger   *slog.Logger
	path     string
	active   *config.Active
	level    *slog.LevelVar
	spool    *spool.Spool
	governor *governor.Governor
}

func (c *configuration) component(asked <-chan os.Signal) agentruntime.Component {
	return agentruntime.Component{
		Name:   "configuration",
		Policy: agentruntime.Essential,
		Run: func(ctx context.Context) error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-asked:
					if err := c.reload(); err != nil {
						return err
					}
				}
			}
		},
	}
}

func (c *configuration) reload() error {
	candidate, err := config.Load(c.path)
	if err == nil {
		err = c.active.Reload(candidate)
	}
	if err != nil {
		c.logger.Error("configuration_not_reloaded", slog.Any("error", err),
			slog.String("running_on", "the configuration the agent read before"),
			slog.String("recovery", recovery(c.path, "", err)))
		return nil
	}
	apply(candidate, c.level)
	if c.spool != nil {
		c.spool.Limit(limits(candidate))
	}
	if c.governor != nil {
		if err := c.governor.Limit(budget(candidate)); err != nil {
			return fmt.Errorf("apply the configuration read from %s: %w", c.path, err)
		}
	}
	c.logger.Info("configuration_reloaded", slog.String("config", c.path), slog.String("log_level", candidate.Logging.Level))
	resources(c.logger, candidate)
	return nil
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

func openCertificates(installation *identity.Installation) (*pki.CertificateFiles, error) {
	directory, err := installation.Directory(certificatesDirectory)
	if err != nil {
		return nil, err
	}
	return pki.OpenCertificateFiles(directory)
}

type credentials struct {
	installation *identity.Installation
	keys         pki.KeyProvider
	certificates *pki.CertificateFiles
}

func (c credentials) Credential() (transport.Credential, error) {
	active, enrolled := c.installation.Enrollment()
	if !enrolled {
		return transport.Credential{}, errors.New("the installation is not enrolled")
	}
	held, err := pki.OpenCredential(c.keys, c.certificates, active.KeyID, active.Certificate.FingerprintSHA256)
	if err != nil {
		return transport.Credential{}, err
	}
	return transport.Credential{Chain: held.Chain, Signer: held.Key}, nil
}

func openSpool(installation *identity.Installation, settings config.Config, logger *slog.Logger) (*spool.Spool, error) {
	directory, err := installation.Directory(spoolDirectory)
	if err != nil {
		return nil, err
	}
	return spool.Open(directory, limits(settings), logger)
}

func limits(settings config.Config) spool.Limits {
	kept := time.Duration(settings.Spool.MaxAge)
	return spool.Limits{
		MaxBytes:       int64(settings.Spool.MaxBytes),
		MaxRecordBytes: int64(settings.Transport.MaxBatchBytes) - protocol.BatchEnvelopeBytes,
		MaxAge: map[spool.Stream]time.Duration{
			spool.Events:    min(kept, protocol.MaxEventAge),
			spool.Inventory: min(kept, protocol.MaxInventoryAge),
		},
	}
}

func budget(settings config.Config) governor.Budget {
	return governor.Budget{
		Scans:                settings.Resources.MaxConcurrentScans,
		ScanBytesPerSecond:   int64(settings.Resources.MaxScanBytesPerSecond),
		Uploads:              settings.Resources.MaxConcurrentUploads,
		UploadBytesPerSecond: int64(settings.Transport.MaxUploadBytesPerSecond),
	}
}

func resources(logger *slog.Logger, settings config.Config) {
	enforced, err := ceilings.Enforced()
	spending(logger, settings, enforced, err)
}

func spending(logger *slog.Logger, settings config.Config, enforced ceilings.Ceilings, err error) {
	reported := []any{
		slog.Group("budgets",
			slog.Int64("memory_limit", int64(settings.Resources.MemoryLimit)),
			slog.Int("max_concurrent_scans", settings.Resources.MaxConcurrentScans),
			slog.Int64("max_scan_bytes_per_second", int64(settings.Resources.MaxScanBytesPerSecond)),
			slog.Int("max_concurrent_uploads", settings.Resources.MaxConcurrentUploads),
			slog.Int64("max_upload_bytes_per_second", int64(settings.Transport.MaxUploadBytesPerSecond))),
		slog.Int("processors", runtime.GOMAXPROCS(0)),
	}
	bound := "let the service that runs the agent bound it, with MemoryMax=, CPUQuota= and TasksMax= or what the platform calls them, and keep resources.memory_limit below the memory it allows"
	if err != nil {
		logger.Warn("agent_resources", append(reported, slog.Any("error", err), slog.String("recovery", bound))...)
		return
	}
	var held []any
	if enforced.Memory > 0 {
		held = append(held, slog.Int64("memory", enforced.Memory))
	}
	if enforced.CPUs > 0 {
		held = append(held, slog.Float64("cpus", enforced.CPUs))
	}
	if enforced.Tasks > 0 {
		held = append(held, slog.Int64("tasks", enforced.Tasks))
	}
	if enforced.Descriptors > 0 {
		held = append(held, slog.Int64("descriptors", enforced.Descriptors))
	}
	unenforced := enforced.Unenforced()
	reported = append(reported, slog.Group("ceilings", held...), slog.Any("unenforced", unenforced))
	above := enforced.Memory > 0 && int64(settings.Resources.MemoryLimit) >= enforced.Memory
	if len(unenforced) == 0 && !above {
		logger.Info("agent_resources", reported...)
		return
	}
	if above {
		reported = append(reported, slog.String("reason", "resources.memory_limit is not below the memory the agent may hold, so the kernel stops it before the garbage collector works to it"))
	}
	logger.Warn("agent_resources", append(reported, slog.String("recovery", bound))...)
}

func backlog(logger *slog.Logger, held spool.Stats) {
	reported := []any{slog.Int64("max_bytes", held.MaxBytes), slog.Int64("bytes", held.Bytes)}
	for _, stream := range held.Streams {
		reported = append(reported, slog.Group(stream.Stream.String(),
			slog.Uint64("outstanding", stream.Outstanding),
			slog.Int64("bytes", stream.Bytes),
			slog.Duration("max_age", stream.MaxAge),
			slog.Uint64("delivered", stream.Delivered),
			slog.Uint64("lost", stream.Lost),
			slog.Uint64("expired", stream.Expired),
			slog.Uint64("quarantined", stream.Quarantined)))
	}
	logger.Info("spool_opened", reported...)
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

func reach(ctx context.Context, path string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	client, err := platform(settings, nil)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	defer client.Close()
	reached := 0
	endpoints := []struct{ name, address string }{{"ingest", settings.Server.IngestURL}, {"renewal", settings.Server.RenewalURL}}
	for _, endpoint := range endpoints {
		peer, err := client.Check(ctx, endpoint.address)
		if err != nil {
			fmt.Fprintf(stderr, "seagull-agent: %s: %v\n", endpoint.name, err)
			fmt.Fprintf(stderr, "seagull-agent: %s\n", recovery(path, "", err))
			continue
		}
		reached++
		asks := "asks for no certificate, so it is not an agent listener"
		if peer.Asks {
			asks = "asks for the certificate of an enrolled agent"
		}
		names := make([]string, 0, len(peer.Names))
		for _, name := range peer.Names {
			names = append(names, secrets.Shown(name))
		}
		fmt.Fprintf(stdout, "%s %s is authenticated: tls 1.3, a certificate for %s issued by %s and valid until %s; it %s\n",
			endpoint.name, endpoint.address, strings.Join(names, ", "), secrets.Shown(peer.Issuer), peer.NotAfter.UTC().Format(time.RFC3339), asks)
	}
	if reached < len(endpoints) {
		return 1
	}
	return 0
}

func platform(settings config.Config, credentials transport.Credentials) (*transport.Client, error) {
	authorities, err := settings.Server.Authorities()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", config.ErrInvalid, err)
	}
	return transport.New(transport.Options{
		Authorities:      authorities,
		Credentials:      credentials,
		ConnectTimeout:   time.Duration(settings.Transport.ConnectTimeout),
		RequestTimeout:   time.Duration(settings.Transport.RequestTimeout),
		MaxResponseBytes: int64(settings.Transport.MaxResponseBytes),
		MaxConnections:   settings.Resources.MaxConcurrentUploads,
	})
}

func ask(path, agentID string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Open(state)
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	defer installation.Close()
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	asked, err := enrollment.Request(installation, keys, agentID, time.Now())
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	if _, err := stdout.Write(asked.Request); err != nil {
		return refuse(path, state, err, stderr)
	}
	switch {
	case asked.Again:
		fmt.Fprintf(stderr, "seagull-agent: installation %s asks again to be agent %s, with the key it asked with before, %s\n", installation.ID(), asked.AgentID, asked.KeyID)
	case asked.Abandoned != "":
		fmt.Fprintf(stderr, "seagull-agent: installation %s asks to be agent %s with a new key, %s, since the key it asked with before, %s, is gone: a certificate issued for that one cannot be imported\n",
			installation.ID(), asked.AgentID, asked.KeyID, asked.Abandoned)
	default:
		fmt.Fprintf(stderr, "seagull-agent: installation %s asks to be agent %s with key %s\n", installation.ID(), asked.AgentID, asked.KeyID)
	}
	fmt.Fprintf(stderr, "seagull-agent: have the platform issue the certificate from this request, as an operator and off this host: POST /v1/agents/%s/certificate on its control plane, with the request as csr_pem\n", asked.AgentID)
	fmt.Fprintf(stderr, "seagull-agent: then activate it with \"seagull-agent -config %s enrollment import ISSUED\", ISSUED holding what the platform answered, as it answered\n", path)
	return 0
}

func accept(path, answer string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	authorities, err := settings.Server.Authorities()
	if err != nil {
		return refuse(path, "", fmt.Errorf("%w: %w", config.ErrInvalid, err), stderr)
	}
	issued, err := answered(answer)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Open(state)
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	defer installation.Close()
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	certificates, err := openCertificates(installation)
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	imported, err := enrollment.Import(installation, keys, certificates, authorities, issued, time.Now())
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	active := imported.Enrollment
	already := ""
	if imported.Already {
		already = ", already"
	}
	fmt.Fprintf(stdout, "installation %s is enrolled as agent %s%s: credential generation %d, certificate %s issued by %s and valid until %s\n",
		installation.ID(), active.AgentID, already, active.Generation, active.Certificate.Serial, secrets.Shown(imported.Issuer), active.Certificate.NotAfter.Format(time.RFC3339))
	for _, authority := range imported.Unheld {
		fmt.Fprintf(stderr, "seagull-agent: the platform tells its agents to trust %s, which server.trust_bundle does not hold: add it to %s before the platform serves or issues certificates from it\n",
			secrets.Shown(authority.Subject.CommonName), settings.Server.TrustBundle)
	}
	return 0
}

func answered(answer string) ([]byte, error) {
	described, err := os.Stat(answer)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", enrollment.ErrUnreadable, secrets.Bounded(err.Error()))
	}
	if !described.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", enrollment.ErrUnreadable, secrets.Shown(answer))
	}
	file, err := os.Open(answer)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", enrollment.ErrUnreadable, secrets.Bounded(err.Error()))
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return nil, fmt.Errorf("%w: %s changed while it was being opened", enrollment.ErrUnreadable, secrets.Shown(answer))
	}
	content, err := io.ReadAll(io.LimitReader(file, enrollment.MaxIssuedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", enrollment.ErrUnreadable, secrets.Bounded(err.Error()))
	}
	return content, nil
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
	fmt.Fprintf(stderr, "seagull-agent: everything the replaced installation held, its keys included, is kept under %s; enroll the new installation with \"seagull-agent -config %s enrollment request AGENT_ID\" before it delivers anything\n",
		filepath.Join(state, "replaced"), path)
	return 0
}

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
	requesting := fmt.Sprintf(`"seagull-agent -config %s enrollment request AGENT_ID"`, path)
	importing := fmt.Sprintf(`"seagull-agent -config %s enrollment import ISSUED"`, path)
	switch {
	case errors.Is(err, config.ErrInvalid):
		return "correct " + path + ", which " + reading + " reads without starting the agent"
	case errors.Is(err, config.ErrNewer):
		return "run the agent release that wrote " + path + ", or write it in the format this release reads"
	case errors.Is(err, config.ErrInsecure):
		return "let the account the agent runs as, and root, change " + path + " and the directory that holds it, and nobody else"
	case errors.Is(err, config.ErrFixed):
		return "stop the agent and start it again for what it settles as it starts to change"
	case errors.Is(err, privileges.ErrInconsistent):
		return "start the agent as the account it runs as: its packaging never starts it through a setuid or setgid program"
	case errors.Is(err, identity.ErrLocked), errors.Is(err, spool.ErrLocked):
		return "stop the agent that holds " + state + ": two agents never share an installation"
	case errors.Is(err, identity.ErrInsecure), errors.Is(err, spool.ErrInsecure), errors.Is(err, pki.ErrCertificateInsecure):
		return "make " + state + " and everything in it belong to the account the agent runs as, closed to its group and to others"
	case errors.Is(err, pki.ErrKeyInsecure):
		return "make " + state + " and everything in it belong to the account the agent runs as, closed to its group and to others; " +
			"if another account could read the key, revoke the certificate issued for it and discard the installation with " + replacement
	case errors.Is(err, identity.ErrNewer), errors.Is(err, spool.ErrNewer):
		return "run the agent release that wrote this state, or discard the installation with " + replacement
	case errors.Is(err, spool.ErrDamaged):
		return "take out of " + filepath.Join(state, spoolDirectory) + " what the agent did not write there, or discard the installation with " + replacement
	case errors.Is(err, identity.ErrDamaged):
		return "restore " + state + " from a backup of this installation, or discard the installation with " + replacement + " and enroll the new one"
	case errors.Is(err, pki.ErrKeyMissing), errors.Is(err, pki.ErrKeyDamaged), errors.Is(err, pki.ErrCertificateMissing), errors.Is(err, pki.ErrCertificateDamaged):
		return "restore " + state + " from a backup of this installation, or have the platform issue it a new certificate: ask with " + requesting + " and activate what it answers with " + importing
	case errors.Is(err, identity.ErrUnasked), errors.Is(err, identity.ErrRefused):
		return "ask to be the agent the platform registered, by the identifier it registered it under: an installation enrolled as one agent never becomes another, which takes a new installation made with " + replacement
	case errors.Is(err, enrollment.ErrNotAsked):
		return "ask for a certificate with " + requesting + ", have the platform issue it, and activate what it answers with " + importing
	case errors.Is(err, enrollment.ErrUnreadable):
		return "import what the platform answered the certificate request with, a seagull.agent.v1.IssuedCertificate, as it answered"
	case errors.Is(err, enrollment.ErrMismatched):
		return "import the certificate the platform issued for the request this installation made, or ask again with " + requesting + " and have the platform issue that one"
	case errors.Is(err, enrollment.ErrUntrusted):
		return "have the certificate issued by the platform server.trust_bundle in " + path + " authenticates, and check that the bundle holds the authority that issues its agents' certificates"
	case errors.Is(err, enrollment.ErrNotCurrent):
		return "check the clock of this host, or have the platform issue the certificate again from the same request"
	case errors.Is(err, identity.ErrNoInstallation):
		return "run the agent to create an installation"
	case errors.Is(err, transport.ErrUntrusted):
		return "check that server.trust_bundle in " + path + " holds the authority that issued the platform's certificate, and that the address names a host that certificate was issued for"
	case errors.Is(err, transport.ErrUnreachable):
		return "check that the host the address names resolves and can be reached from this machine over the network"
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
