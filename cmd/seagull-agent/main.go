package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/delivery"
	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/authentication"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/inventory"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/ceilings"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dumps"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/privileges"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

const (
	keysDirectory         = "keys"
	certificatesDirectory = "certificates"
	trustDirectory        = "trust"
	spoolDirectory        = "spool"
	statusDirectory       = "status"
	collectionDirectory   = "collection"
	statusEvery           = 30 * time.Second
)

const usage = `Usage:
  seagull-agent -config FILE run                          run the agent until it receives SIGINT or SIGTERM
  seagull-agent -config FILE config check                 read the configuration, report what it refuses, and exit
  seagull-agent -config FILE config print                 print the configuration the agent would run on, and exit
  seagull-agent -config FILE platform check               authenticate the platform the configuration names, presenting and sending nothing, and exit
  seagull-agent -config FILE enrollment request AGENT_ID  ask for a certificate as AGENT_ID, printing the request the platform issues it from
  seagull-agent -config FILE enrollment import ISSUED     activate the certificate the platform answered the request with, held in ISSUED
  seagull-agent -config FILE enrollment renew             ask the platform for the next certificate now, as the enrolled agent
  seagull-agent -config FILE installation replace         replace the installation with a new one that is not enrolled
  seagull-agent -config FILE status                       print what the agent last said of itself, and exit with 0 only while it runs as it should
  seagull-agent -config FILE diagnostics BUNDLE           write what helps troubleshoot the agent, and nothing that authenticates it, into the new file BUNDLE
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
	case configured && slices.Equal(flags.Args(), []string{"enrollment", "renew"}):
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return renew(ctx, *path, stdout, stderr)
	case configured && slices.Equal(flags.Args(), []string{"installation", "replace"}):
		return replace(*path, stdout, stderr)
	case configured && slices.Equal(flags.Args(), []string{"status"}):
		return report(*path, stdout, stderr)
	case configured && flags.NArg() == 2 && flags.Arg(0) == "diagnostics":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return diagnose(ctx, *path, flags.Arg(1), stdout, stderr)
	}
	flags.Usage()
	return 2
}

func serve(ctx context.Context, stderr io.Writer, path string, components ...agentruntime.Component) int {
	began := time.Now()
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
	privileged(logger, granted)
	memory(logger, withheld)
	resources(logger, settings)
	state := settings.Identity.StateDirectory
	held := &configuration{logger: logger, path: path, active: config.Activate(settings), level: level, applied: began}
	refused := func(err error) int {
		logger.Error("agent_not_started", slog.Any("error", err), slog.String("recovery", recovery(path, state, err)))
		return 1
	}

	asked := make(chan os.Signal, 1)
	signal.Notify(asked, syscall.SIGHUP)
	defer signal.Stop(asked)
	installation, err := identity.Open(state)
	if err != nil {
		return refused(err)
	}
	defer installation.Close()
	if installation.Created() {
		logger.Info("installation_created", slog.String("installation_id", installation.ID()), slog.String("state", state))
	}
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		return refused(err)
	}
	certificates, err := openCertificates(installation)
	if err != nil {
		return refused(err)
	}
	authorities, err := openAuthorities(installation)
	if err != nil {
		return refused(err)
	}
	chosen, unread := trusted(settings, holding(installation), authorities.Open)
	if errors.Is(unread, config.ErrInvalid) {
		return refused(unread)
	}
	started := []any{slog.String("build", buildIdentity()), slog.String("config", path)}
	for _, spoken := range wireVersions() {
		started = append(started, slog.Int(spoken.name, spoken.version))
	}
	started = append(started, slog.String("installation_id", installation.ID()))
	credential := &credentials{installation: installation, keys: keys, certificates: certificates}
	enrolled, isEnrolled := installation.Enrollment()
	if isEnrolled {
		if _, err := credential.Credential(); err != nil {
			return refused(err)
		}
		started = append(started, slog.String("agent_id", enrolled.AgentID), slog.Uint64("credential_generation", enrolled.Generation))
	}
	posture := keys.Posture()
	started = append(started, slog.String("key_provider", posture.Provider), slog.Bool("key_exportable", posture.Exportable), slog.String("trust", chosen.source))
	spooled, err := openSpool(installation, settings, logger)
	if err != nil {
		return refused(err)
	}
	defer spooled.Close()
	held.spool = spooled
	backlog(logger, spooled.Stats())
	governed, err := governor.New(logger, installation.ID(), budget(settings))
	if err != nil {
		return refused(err)
	}
	held.governor = governed
	observed := &observing{began: began, path: path, state: state, installation: installation, spool: spooled, governor: governed, configuration: held}
	collected, err := collect(installation, held.active, spooled, governed, logger)
	if err != nil {
		return refused(err)
	}
	held.collection = collected.collection
	observed.collection, observed.authentication, observed.inventory = collected.collection, collected.authentication, collected.inventory
	composed := append([]agentruntime.Component{held.component(asked), {Name: "collection", Policy: agentruntime.Optional, Run: collected.collection.Run}}, components...)
	if isEnrolled {
		client, err := platform(settings, chosen.authorities, credential)
		if err != nil {
			return refused(err)
		}
		defer client.Close()
		renewer, err := renewal.New(renewal.Options{
			Installation: installation,
			Keys:         keys,
			Certificates: certificates,
			Authorities:  authorities,
			Client:       client,
			URL:          settings.Server.RenewalURL,
			Trusted:      chosen.authorities,
			Configured:   chosen.configured,
			KeyLifetime:  func() time.Duration { return time.Duration(held.active.Settings().Identity.KeyLifetime) },
			Logger:       logger,
			Recovery:     func(err error) string { return recovery(path, state, err) },
		})
		if err != nil {
			return refused(err)
		}
		composed = append(composed, agentruntime.Component{Name: "renewal", Policy: agentruntime.Optional, Run: renewer.Run})
		observed.renewer = renewer
		delivered, err := delivery.New(delivery.Options{
			Spool:    spooled,
			Client:   client,
			Governor: governed,
			URL:      settings.Server.IngestURL,
			Batching: func() delivery.Batching { return batching(held.active.Settings()) },
			Logger:   logger,
			Recovery: func(err error) string { return recovery(path, state, err) },
		})
		if err != nil {
			return refused(err)
		}
		composed = append(composed, agentruntime.Component{Name: "delivery", Policy: agentruntime.Essential, Run: delivered.Run})
		observed.delivery = delivered
	}
	kept, err := installation.Directory(statusDirectory)
	if err != nil {
		return refused(err)
	}
	keeper, err := status.NewKeeper(kept, statusEvery, observed.snapshot, logger)
	if err != nil {
		return refused(err)
	}
	composed = append(composed, agentruntime.Component{Name: "status", Policy: agentruntime.Optional, Run: keeper.Run})
	agent, err := agentruntime.New(logger, time.Duration(settings.Resources.ShutdownTimeout), composed...)
	if err != nil {
		logger.Error("agent_not_started", slog.Any("error", err))
		return 1
	}
	trust(logger, chosen, unread)
	logger.Info("agent_starting", started...)
	if err := agent.Run(ctx); err != nil {
		keeper.Stopped("the agent stopped as it could not run on: " + err.Error())
		logger.Error("agent_stopped", slog.Any("error", err))
		return 1
	}
	keeper.Stopped("the agent was asked to stop")
	logger.Info("agent_stopped")
	return 0
}

func unstarted(stderr io.Writer, path string, err error) int {
	slog.New(slog.NewJSONHandler(stderr, nil)).Error("agent_not_started",
		slog.Any("error", err), slog.String("recovery", recovery(path, "", err)))
	return 1
}

// The capabilities the agent needs beyond the account it runs as: none. Its
// installation, its keys and its settings are files that account reaches, the
// platform is a network service like any other, the authentication collector
// reads the system journal as a member of systemd-journal, a group, and the
// inventory collector reads what the host shows any account.
func needed() []string { return nil }

func privileged(logger *slog.Logger, granted privileges.Privileges) {
	reported := []any{
		slog.Int("user", granted.User),
		slog.Int("group", granted.Group),
		slog.Any("groups", granted.Groups),
		slog.Any("capabilities", granted.Capabilities),
		slog.Bool("no_new_privs", granted.NoNewPrivs),
		slog.String("seccomp", granted.Seccomp),
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
	logger     *slog.Logger
	path       string
	active     *config.Active
	level      *slog.LevelVar
	spool      *spool.Spool
	governor   *governor.Governor
	collection *modules.Collection

	mu        sync.Mutex
	applied   time.Time
	refused   error
	refusedAt time.Time
	hint      string
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
		hint := recovery(c.path, "", err)
		c.mu.Lock()
		c.refused, c.refusedAt, c.hint = err, time.Now(), hint
		c.mu.Unlock()
		c.logger.Error("configuration_not_reloaded", slog.Any("error", err),
			slog.String("running_on", "the configuration the agent read before"),
			slog.String("recovery", hint))
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
	if c.collection != nil {
		if err := c.collection.Apply(enabled(candidate)); err != nil {
			return fmt.Errorf("apply the configuration read from %s: %w", c.path, err)
		}
	}
	c.mu.Lock()
	c.refused, c.applied = nil, time.Now()
	c.mu.Unlock()
	c.logger.Info("configuration_reloaded", slog.String("config", c.path), slog.String("log_level", candidate.Logging.Level))
	resources(c.logger, candidate)
	return nil
}

type collectors struct {
	collection     *modules.Collection
	authentication *authentication.Collector
	inventory      *inventory.Collector
}

func collect(installation *identity.Installation, active *config.Active, spooled *spool.Spool, governed *governor.Governor, logger *slog.Logger) (collectors, error) {
	directory, err := installation.Directory(collectionDirectory)
	if err != nil {
		return collectors{}, err
	}
	authenticating, err := authentication.New(authentication.Options{
		Installation: installation.ID(),
		Spool:        spooled,
		Governor:     governed,
		Directory:    directory,
		Logger:       logger,
	})
	if err != nil {
		return collectors{}, err
	}
	taking, err := inventory.New(inventory.Options{
		Installation: installation.ID(),
		Spool:        spooled,
		Governor:     governed,
		Directory:    directory,
		Logger:       logger,
		Interval:     func() time.Duration { return time.Duration(active.Settings().Modules[inventory.Name].Interval) },
		Largest:      func() int64 { return int64(active.Settings().Transport.MaxBatchBytes) - protocol.BatchEnvelopeBytes },
	})
	if err != nil {
		return collectors{}, err
	}
	settings := active.Settings()
	collection, err := modules.New(logger, modules.Policy{},
		modules.Module{Name: authentication.Name, Enabled: slices.Contains(enabled(settings), authentication.Name), Collect: authenticating.Collect},
		modules.Module{Name: inventory.Name, Enabled: slices.Contains(enabled(settings), inventory.Name), Collect: taking.Collect},
	)
	if err != nil {
		return collectors{}, err
	}
	return collectors{collection: collection, authentication: authenticating, inventory: taking}, nil
}

func enabled(settings config.Config) []string {
	var named []string
	for _, name := range slices.Sorted(maps.Keys(settings.Modules)) {
		if settings.Modules[name].Enabled {
			named = append(named, name)
		}
	}
	return named
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

func openAuthorities(installation *identity.Installation) (*pki.AuthorityFiles, error) {
	directory, err := installation.Directory(trustDirectory)
	if err != nil {
		return nil, err
	}
	return pki.OpenAuthorityFiles(directory)
}

type credentials struct {
	installation *identity.Installation
	keys         pki.KeyProvider
	certificates *pki.CertificateFiles
	mu           sync.Mutex
	opened       string
	held         transport.Credential
}

func (c *credentials) Credential() (transport.Credential, error) {
	active, enrolled := c.installation.Enrollment()
	if !enrolled {
		return transport.Credential{}, errors.New("the installation is not enrolled")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opened == active.Certificate.FingerprintSHA256 {
		return c.held, nil
	}
	held, err := pki.OpenCredential(c.keys, c.certificates, active.KeyID, active.Certificate.FingerprintSHA256)
	if err != nil {
		return transport.Credential{}, err
	}
	c.opened, c.held = active.Certificate.FingerprintSHA256, transport.Credential{Chain: held.Chain, Signer: held.Key}
	return c.held, nil
}

type trusting struct {
	authorities []*x509.Certificate
	source      string
	configured  string
	adopted     identity.Trust
	reset       bool
}

func trusted(settings config.Config, adopted func() (identity.Trust, bool, error), open func(string) ([]*x509.Certificate, error)) (trusting, error) {
	configured, err := settings.Server.Authorities()
	if err != nil {
		return trusting{}, fmt.Errorf("%w: %w", config.ErrInvalid, err)
	}
	chosen := trusting{authorities: configured, source: "server.trust_bundle", configured: pki.Digest(configured)}
	held, found, err := adopted()
	switch {
	case err != nil || !found:
		return chosen, err
	case held.Configured != chosen.configured:
		chosen.reset = true
		return chosen, nil
	}
	authorities, err := open(held.Authorities)
	if err != nil {
		return chosen, err
	}
	chosen.authorities, chosen.source, chosen.adopted = authorities, "published", held
	return chosen, nil
}

func holding(installation *identity.Installation) func() (identity.Trust, bool, error) {
	return func() (identity.Trust, bool, error) {
		held, found := installation.Trust()
		return held, found, nil
	}
}

func trust(logger *slog.Logger, chosen trusting, unread error) {
	switch {
	case unread != nil:
		logger.Warn("authorities_not_read", slog.Any("error", unread), slog.String("trust", chosen.source),
			slog.String("recovery", "nothing: the agent authenticates the platform against server.trust_bundle until a renewal adopts the authorities the platform publishes again"))
	case chosen.reset:
		logger.Info("authorities_reset", slog.String("trust", chosen.source),
			slog.String("reason", "server.trust_bundle changed since the agent adopted the authorities the platform published, and the operator's word is the newer"))
	}
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

func batching(settings config.Config) delivery.Batching {
	return delivery.Batching{
		MaxBytes:            int(settings.Transport.MaxBatchBytes),
		MaxEvents:           settings.Transport.MaxEventsPerBatch,
		MaxInventoryRecords: settings.Transport.MaxInventoryRecordsPerBatch,
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
	state := settings.Identity.StateDirectory
	chosen, unread := trusted(settings, func() (identity.Trust, bool, error) { return identity.Adopted(state) }, func(digest string) ([]*x509.Certificate, error) {
		root, err := os.OpenRoot(filepath.Join(state, trustDirectory))
		if err != nil {
			return nil, err
		}
		defer root.Close()
		return pki.ReadAuthorities(root, digest)
	})
	if errors.Is(unread, config.ErrInvalid) {
		return refuse(path, "", unread, stderr)
	}
	if unread != nil {
		fmt.Fprintf(stderr, "seagull-agent: the authorities the installation adopted cannot be read, so the platform is checked against server.trust_bundle: %v\n", unread)
	}
	client, err := platform(settings, chosen.authorities, nil)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	defer client.Close()
	reached := 0
	endpoints := []struct{ name, address string }{{"ingest", settings.Server.IngestURL}, {"renewal", settings.Server.RenewalURL}}
	for _, endpoint := range endpoints {
		peer, err := client.Check(ctx, endpoint.address)
		if err != nil {
			hint := recovery(path, "", err)
			if chosen.source == "published" && errors.Is(err, transport.ErrUntrusted) {
				hint = "check that an authority the platform published to the installation issued the listener's certificate, and that the address names a host that certificate was issued for"
			}
			fmt.Fprintf(stderr, "seagull-agent: %s: %v\n", endpoint.name, err)
			fmt.Fprintf(stderr, "seagull-agent: %s\n", hint)
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
	published := fmt.Sprintf("the platform was checked against the %s it published to the installation at %s, which the agent trusts in place of server.trust_bundle",
		counted(len(chosen.authorities)), chosen.adopted.AdoptedAt.Format(time.RFC3339))
	if reached < len(endpoints) {
		if chosen.source == "published" {
			fmt.Fprintf(stderr, "seagull-agent: %s\n", published)
		}
		return 1
	}
	if chosen.source == "published" {
		fmt.Fprintln(stdout, published)
	}
	return 0
}

func platform(settings config.Config, authorities []*x509.Certificate, credentials transport.Credentials) (*transport.Client, error) {
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
	refused := func(state string, err error) int {
		audit(stderr, slog.LevelWarn, "enrollment_not_requested", slog.String("config", path), slog.String("agent_id", secrets.Bounded(agentID)), slog.Any("error", err))
		return refuse(path, state, err, stderr)
	}
	settings, err := config.Load(path)
	if err != nil {
		return refused("", err)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Open(state)
	if err != nil {
		return refused(state, err)
	}
	defer installation.Close()
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		return refused(state, err)
	}
	asked, err := enrollment.Request(installation, keys, agentID, time.Now())
	if err != nil {
		return refused(state, err)
	}
	if _, err := stdout.Write(asked.Request); err != nil {
		return refused(state, err)
	}
	audit(stderr, slog.LevelInfo, "enrollment_requested", slog.String("config", path), slog.String("installation_id", installation.ID()),
		slog.String("agent_id", asked.AgentID), slog.String("key_id", asked.KeyID), slog.Bool("again", asked.Again), slog.String("abandoned", asked.Abandoned))
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
	refused := func(state string, err error) int {
		audit(stderr, slog.LevelWarn, "credential_not_imported", slog.String("config", path), slog.String("issued", secrets.Bounded(answer)), slog.Any("error", err))
		return refuse(path, state, err, stderr)
	}
	settings, err := config.Load(path)
	if err != nil {
		return refused("", err)
	}
	issued, err := answered(answer)
	if err != nil {
		return refused("", err)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Open(state)
	if err != nil {
		return refused(state, err)
	}
	defer installation.Close()
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		return refused(state, err)
	}
	certificates, err := openCertificates(installation)
	if err != nil {
		return refused(state, err)
	}
	held, err := openAuthorities(installation)
	if err != nil {
		return refused(state, err)
	}
	chosen, unread := trusted(settings, holding(installation), held.Open)
	if errors.Is(unread, config.ErrInvalid) {
		return refused(state, unread)
	}
	if unread != nil {
		fmt.Fprintf(stderr, "seagull-agent: the authorities the installation adopted cannot be read, so the certificate is verified against server.trust_bundle: %v\n", unread)
	}
	authorities := chosen.authorities
	imported, err := enrollment.Import(installation, keys, certificates, authorities, issued, time.Now())
	if err != nil {
		return refused(state, err)
	}
	active := imported.Enrollment
	audit(stderr, slog.LevelInfo, "credential_imported", slog.String("config", path), slog.String("issued", secrets.Bounded(answer)),
		slog.String("installation_id", installation.ID()), slog.String("agent_id", active.AgentID), slog.Uint64("credential_generation", active.Generation),
		slog.String("key_id", active.KeyID), slog.String("serial", active.Certificate.Serial), slog.Time("not_after", active.Certificate.NotAfter), slog.Bool("already", imported.Already))
	already := ""
	if imported.Already {
		already = ", already"
	}
	fmt.Fprintf(stdout, "installation %s is enrolled as agent %s%s: credential generation %d, certificate %s issued by %s and valid until %s\n",
		installation.ID(), active.AgentID, already, active.Generation, active.Certificate.Serial, secrets.Shown(imported.Issuer), active.Certificate.NotAfter.Format(time.RFC3339))
	for _, authority := range imported.Unheld {
		fmt.Fprintf(stderr, "seagull-agent: the platform tells its agents to trust %s, which the agent does not: add it to %s before the platform serves or issues certificates from it, or let the agent adopt it as it renews\n",
			secrets.Shown(authority.Subject.CommonName), settings.Server.TrustBundle)
	}
	return 0
}

func renew(ctx context.Context, path string, stdout, stderr io.Writer) int {
	refused := func(state string, err error) int {
		audit(stderr, slog.LevelWarn, "credential_not_renewed", slog.String("config", path), slog.Any("error", err))
		return refuse(path, state, err, stderr)
	}
	settings, err := config.Load(path)
	if err != nil {
		return refused("", err)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Open(state)
	if err != nil {
		return refused(state, err)
	}
	defer installation.Close()
	keys, err := openKeys(installation, settings.Identity.KeyProvider)
	if err != nil {
		return refused(state, err)
	}
	certificates, err := openCertificates(installation)
	if err != nil {
		return refused(state, err)
	}
	authorities, err := openAuthorities(installation)
	if err != nil {
		return refused(state, err)
	}
	if _, enrolled := installation.Enrollment(); !enrolled {
		return refused(state, renewal.ErrNotEnrolled)
	}
	chosen, unread := trusted(settings, holding(installation), authorities.Open)
	if errors.Is(unread, config.ErrInvalid) {
		return refused(state, unread)
	}
	if unread != nil {
		fmt.Fprintf(stderr, "seagull-agent: the authorities the installation adopted cannot be read, so the platform is authenticated against server.trust_bundle: %v\n", unread)
	}
	credential := &credentials{installation: installation, keys: keys, certificates: certificates}
	if _, err := credential.Credential(); err != nil {
		return refused(state, err)
	}
	client, err := platform(settings, chosen.authorities, credential)
	if err != nil {
		return refused(state, err)
	}
	defer client.Close()
	renewer, err := renewal.New(renewal.Options{
		Installation: installation,
		Keys:         keys,
		Certificates: certificates,
		Authorities:  authorities,
		Client:       client,
		URL:          settings.Server.RenewalURL,
		Trusted:      chosen.authorities,
		Configured:   chosen.configured,
		KeyLifetime:  func() time.Duration { return time.Duration(settings.Identity.KeyLifetime) },
		Logger:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return refused(state, err)
	}
	renewed, err := renewer.Renew(ctx)
	if err != nil {
		return refused(state, err)
	}
	next, key, kept := renewed.Enrollment, "with the key it held", "kept"
	if renewed.Rotated {
		key, kept = "with a new key, "+next.KeyID, "rotated"
	}
	audit(stderr, slog.LevelInfo, "credential_renewed", slog.String("config", path), slog.String("installation_id", installation.ID()),
		slog.String("agent_id", next.AgentID), slog.Uint64("credential_generation", next.Generation), slog.String("key", kept), slog.String("key_id", next.KeyID),
		slog.String("serial", next.Certificate.Serial), slog.Time("not_after", next.Certificate.NotAfter), slog.Bool("adopted", renewed.Adopted))
	fmt.Fprintf(stdout, "installation %s renewed agent %s to credential generation %d, %s: certificate %s issued by %s and valid until %s\n",
		installation.ID(), next.AgentID, next.Generation, key, next.Certificate.Serial, secrets.Shown(renewed.Issuer), next.Certificate.NotAfter.Format(time.RFC3339))
	switch {
	case renewed.Adopted:
		fmt.Fprintf(stdout, "it authenticates the platform against the %s the platform published from now on\n", counted(len(renewed.Authorities)))
	case renewed.Kept != nil:
		fmt.Fprintf(stderr, "seagull-agent: %v\n", renewed.Kept)
		fmt.Fprintf(stderr, "seagull-agent: %s\n", recovery(path, state, renewed.Kept))
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

func counted(count int) string {
	if count == 1 {
		return "1 authority"
	}
	return fmt.Sprintf("%d authorities", count)
}

func replace(path string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		audit(stderr, slog.LevelWarn, "installation_not_replaced", slog.String("config", path), slog.Any("error", err))
		return refuse(path, "", err, stderr)
	}
	state := settings.Identity.StateDirectory
	installation, err := identity.Replace(state)
	if err != nil {
		audit(stderr, slog.LevelWarn, "installation_not_replaced", slog.String("config", path), slog.String("state", state), slog.Any("error", err))
		return refuse(path, state, err, stderr)
	}
	defer installation.Close()
	audit(stderr, slog.LevelInfo, "installation_replaced", slog.String("config", path), slog.String("state", state),
		slog.String("installation_id", installation.ID()), slog.String("replaces", installation.Replaces()))
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
	reissuing := "have the platform issue the installation a new certificate, as an operator and with the agent stopped: ask with " + requesting + " and activate what it answers with " + importing
	var refused *renewal.Refusal
	if errors.As(err, &refused) {
		switch {
		case refused.Code == "illegal_move":
			return "the platform no longer renews the certificate this installation presents: when an operator disabled the agent, they enable it again; when it was revoked or decommissioned, they replace the installation with " + replacement +
				" and enroll it as a new agent; when the platform says the certificate was already replaced, it holds a newer certificate of this agent that this installation never activated, because the answer to a renewal was lost or because another installation holds this installation's key: if the key may have been copied, an operator revokes the agent and replaces the installation, and otherwise they " +
				reissuing + "; the agent never enrolls itself again"
		case refused.Code == "unknown_agent":
			return "the platform knows no such agent: an operator registers a new one, replaces the installation with " + replacement + " and enrolls it as that agent"
		case refused.Status == 429:
			return "nothing: the platform bounds how often an agent renews, and the agent asks again later"
		case refused.Status >= 500:
			return "nothing: the agent asks again later, and the platform's operators find in its log why it did not answer"
		}
		return "check that server.renewal_url in " + path + " names the platform's renewal listener, and run an agent release that platform renews"
	}
	var excluded *protocol.Exclusion
	var unspoken *protocol.Incompatibility
	var disputed *protocol.Dispute
	var answered *protocol.Refusal
	switch {
	case errors.As(err, &excluded) && excluded.Reason == protocol.Unidentified:
		return "the platform reads no agent in the certificate this installation presents: " + reissuing
	case errors.As(err, &excluded) && excluded.Reason == protocol.Unregistered:
		return "the platform knows no such agent: an operator registers the agent this installation was enrolled as; the records wait meanwhile, and are never sent as another agent"
	case errors.As(err, &excluded):
		return "the platform no longer admits this agent: an operator admits it again, or, when it was revoked or decommissioned, replaces the installation with " + replacement +
			" and enrolls it as a new agent, and the records this installation holds are never sent as that one"
	case errors.As(err, &unspoken):
		return "run an agent release the platform takes, or a platform that takes what this agent sends: the records wait meanwhile, and expire when neither comes in time"
	case errors.As(err, &disputed):
		return "check the clock of this host against the platform's: the records wait until the platform admits the moments they carry, or until they expire"
	case errors.As(err, &answered), errors.Is(err, protocol.ErrNoAcknowledgement):
		return "check that server.ingest_url in " + path + " names the platform's ingest listener, and run an agent release that platform takes"
	}
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
	case errors.Is(err, spool.ErrUnavailable):
		return "restart the agent once the filesystem that holds " + filepath.Join(state, spoolDirectory) + " takes writes again: a spool that could not make a record durable admits nothing until the agent starts again"
	case errors.Is(err, status.ErrUnwritten):
		return "start the agent: it writes its status as it starts, and every " + statusEvery.String() + " while it runs"
	case errors.Is(err, status.ErrInsecure):
		return "read the status as the account the agent runs as, and keep " + state + " private to that account"
	case errors.Is(err, status.ErrNewer):
		return "run the agent release that wrote the status, or start this one, which writes it anew"
	case errors.Is(err, status.ErrDamaged):
		return "start the agent again: it writes its status anew as it starts"
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
	case errors.Is(err, renewal.ErrNotEnrolled):
		return "enroll the installation first: ask with " + requesting + " and activate what the platform answers with " + importing
	case errors.Is(err, renewal.ErrExpired):
		return reissuing + ": a certificate that expired cannot renew itself"
	case errors.Is(err, renewal.ErrNotAdoptable):
		return "issue the platform's renewal listener a certificate from an authority the platform publishes: the agent adopts them as it next renews, and authenticates the platform against the ones it trusts until then"
	case errors.Is(err, transport.ErrRefused):
		return "the platform refused the agent's certificate: " + reissuing
	case errors.Is(err, transport.ErrUnauthenticated):
		return "check the clock of this host; if the certificate of the active generation expired, " + reissuing
	case errors.Is(err, transport.ErrReplyTooLarge):
		return "raise transport.max_response_bytes in " + path + " above the size of the platform's answers"
	case errors.Is(err, identity.ErrNoInstallation):
		return "run the agent to create an installation"
	case errors.Is(err, transport.ErrUntrusted):
		return "check that server.trust_bundle in " + path + " holds the authority that issued the platform's certificate, and that the address names a host that certificate was issued for"
	case errors.Is(err, transport.ErrUnanswered):
		return "nothing: the agent asks again; if the platform keeps taking requests it does not answer, check that it answers within transport.request_timeout in " + path
	case errors.Is(err, transport.ErrUnreachable):
		return "check that the host the address names resolves and can be reached from this machine over the network"
	case errors.Is(err, diagnostics.ErrExists):
		return "name a file that is not there yet: a bundle never replaces one, so whatever is there stays as it was"
	case errors.Is(err, diagnostics.ErrInstallation):
		return "write the bundle outside the directories the agent keeps as its own, its installation among them, such as in /var/tmp, and read it there as root"
	case errors.Is(err, syscall.EROFS):
		return "let the agent write " + state + ": its filesystem is read-only to the agent, and the service the package installs leaves it writable in /var/lib/seagull-agent alone, so keep the installation there or name its directory in ReadWritePaths= with a drop-in"
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
