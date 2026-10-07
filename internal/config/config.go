package config

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const Format = 1

const (
	KeysInFiles = "filesystem"
	JSONLogs    = "json"
	TextLogs    = "text"
)

const (
	maxConfigBytes  = 64 << 10
	maxBundleBytes  = 1 << 20
	maxCertificates = 64
	maxPathBytes    = 4 << 10
	batchesSpooled  = 4
	maxGroups       = 8
	maxWatchedPaths = 64
	maxExcluded     = 256
	maxNameBytes    = 255
	watcher         = "files"
)

var (
	ErrInvalid  = errors.New("the configuration is invalid")
	ErrNewer    = errors.New("the configuration was written for a newer agent")
	ErrInsecure = errors.New("the configuration can be changed by another account")
	ErrFixed    = errors.New("the configuration cannot change while the agent runs")
)

var (
	levels     = map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}
	logFormats = []string{JSONLogs, TextLogs}
	providers  = []string{KeysInFiles}
	collectors = []string{"authentication", "files", "inventory", "processes"}
	periodic   = map[string]Duration{"files": Duration(time.Hour), "inventory": Duration(time.Hour), "processes": Duration(time.Hour)}
	watched    = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib/systemd/system", "/boot", "/var/spool/cron"}
	unwatched  = []string{"/proc", "/sys", "/dev", "/tmp", "/var/tmp"}
)

type Config struct {
	Format    int       `json:"format"`
	Identity  Identity  `json:"identity"`
	Server    Server    `json:"server"`
	Transport Transport `json:"transport"`
	Spool     Spool     `json:"spool"`
	Modules   Modules   `json:"modules"`
	Resources Resources `json:"resources"`
	Logging   Logging   `json:"logging"`
	Updates   Updates   `json:"updates"`
}

// Where the installation lives and what holds its keys. It does not name the
// agent: the platform issues a certificate for an agent an operator registered,
// and enrollment writes that name into the installation.
type Identity struct {
	StateDirectory string   `json:"state_directory"`
	KeyProvider    string   `json:"key_provider"`
	KeyLifetime    Duration `json:"key_lifetime"`
}

type Server struct {
	IngestURL   string `json:"ingest_url"`
	RenewalURL  string `json:"renewal_url"`
	TrustBundle string `json:"trust_bundle"`
}

type Transport struct {
	ConnectTimeout              Duration `json:"connect_timeout"`
	RequestTimeout              Duration `json:"request_timeout"`
	MaxBatchBytes               Size     `json:"max_batch_bytes"`
	MaxEventsPerBatch           int      `json:"max_events_per_batch"`
	MaxInventoryRecordsPerBatch int      `json:"max_inventory_records_per_batch"`
	MaxResponseBytes            Size     `json:"max_response_bytes"`
	MaxUploadBytesPerSecond     Size     `json:"max_upload_bytes_per_second"`
}

type Spool struct {
	MaxBytes Size     `json:"max_bytes"`
	MaxAge   Duration `json:"max_age"`
}

type Modules map[string]Module

// A module collects while it is enabled. One that takes stock of the host
// rather than follow a source does it every interval, which a module that
// follows a source has none of, and the one that watches files watches the
// paths it is given, less what it is told to leave out.
type Module struct {
	Enabled  bool     `json:"enabled"`
	Interval Duration `json:"interval,omitzero"`
	Paths    []string `json:"paths,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}

// The decoder names a setting by its path through the groups it is in, and a
// module's name is the key of a group rather than one of its settings, so a
// module's settings are decoded here, each refusal named with its module.
func (m *Modules) UnmarshalJSON(content []byte) error {
	var written map[string]json.RawMessage
	if err := json.Unmarshal(content, &written); err != nil {
		return err
	}
	held := make(Modules, len(written))
	for name, settings := range written {
		decoder := json.NewDecoder(bytes.NewReader(settings))
		decoder.DisallowUnknownFields()
		var module Module
		if err := decoder.Decode(&module); err != nil {
			var mistyped *json.UnmarshalTypeError
			if errors.As(err, &mistyped) {
				mistyped.Field = join(name, mistyped.Field)
			}
			return err
		}
		held[name] = module
	}
	*m = held
	return nil
}

type Resources struct {
	MemoryLimit           Size     `json:"memory_limit"`
	MaxConcurrentScans    int      `json:"max_concurrent_scans"`
	MaxScanBytesPerSecond Size     `json:"max_scan_bytes_per_second"`
	MaxConcurrentUploads  int      `json:"max_concurrent_uploads"`
	ShutdownTimeout       Duration `json:"shutdown_timeout"`
}

type Logging struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type Updates struct {
	Enabled bool `json:"enabled"`
}

func (l Logging) Severity() slog.Level { return levels[l.Level] }

func defaults() Config {
	return Config{
		Format:   Format,
		Identity: Identity{KeyProvider: KeysInFiles, KeyLifetime: Duration(720 * time.Hour)},
		Transport: Transport{
			ConnectTimeout:              Duration(10 * time.Second),
			RequestTimeout:              Duration(30 * time.Second),
			MaxBatchBytes:               4 << 20,
			MaxEventsPerBatch:           1000,
			MaxInventoryRecordsPerBatch: 64,
			MaxResponseBytes:            64 << 10,
			MaxUploadBytesPerSecond:     1 << 20,
		},
		Spool:   Spool{MaxBytes: 512 << 20, MaxAge: Duration(72 * time.Hour)},
		Modules: Modules{},
		Resources: Resources{
			MemoryLimit:           256 << 20,
			MaxConcurrentScans:    2,
			MaxScanBytesPerSecond: 8 << 20,
			MaxConcurrentUploads:  1,
			ShutdownTimeout:       Duration(10 * time.Second),
		},
		Logging: Logging{Level: "info", Format: JSONLogs},
	}
}

// Load reads the configuration in path and returns it only once every setting
// it holds, and every setting it leaves to a default, is one the agent runs on.
func Load(path string) (Config, error) {
	content, err := read(path)
	if err != nil {
		return Config{}, err
	}
	settings, err := parse(content)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := settings.validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return settings, nil
}

func (c Config) Encode() ([]byte, error) {
	if c.Modules == nil {
		c.Modules = Modules{}
	}
	content, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode the configuration: %w", err)
	}
	return append(content, '\n'), nil
}

func read(path string) ([]byte, error) {
	described, err := os.Lstat(path)
	switch {
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, path)
	}
	directory := filepath.Dir(path)
	holder, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", directory, err)
	}
	for _, inspected := range []struct {
		path string
		info fs.FileInfo
	}{{path: path, info: described}, {path: directory, info: holder}} {
		if err := files.Trusted(inspected.info); err != nil {
			if errors.Is(err, errors.ErrUnsupported) {
				return nil, fmt.Errorf("read the configuration in %s: %w", inspected.path, err)
			}
			return nil, fmt.Errorf("%w: %s %v", ErrInsecure, inspected.path, err)
		}
	}
	content, err := contents(path, described, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %v", ErrInvalid, path, err)
	}
	return content, nil
}

func contents(path string, described fs.FileInfo, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return nil, errors.New("changed while it was being read")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("is larger than %d bytes", limit)
	}
	return content, nil
}

func parse(content []byte) (Config, error) {
	if err := scan(content); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var declared struct {
		Format *int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, explain(err))
	}
	switch {
	case declared.Format == nil:
		return Config{}, fmt.Errorf("%w: it declares no format, and this agent reads format %d", ErrInvalid, Format)
	case *declared.Format > Format:
		return Config{}, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, *declared.Format, Format)
	case *declared.Format != Format:
		return Config{}, fmt.Errorf("%w: format %d is not one this agent reads", ErrInvalid, *declared.Format)
	}
	settings := defaults()
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, explain(err))
	}
	return settings, nil
}

// A setting written twice, or written as null, says two things at once, and
// the agent refuses both rather than pick the meaning the decoder happens to keep.
func scan(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := scanValue(decoder, "", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("it holds more than one document")
	}
	return nil
}

func scanValue(decoder *json.Decoder, path string, depth int) error {
	if depth > maxGroups {
		return fmt.Errorf("%s holds more than %d groups of settings", setting(path), maxGroups)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("it is not a configuration: %v", err)
	}
	opened, group := token.(json.Delim)
	switch {
	case token == nil:
		return fmt.Errorf("%s is null, and a setting the file leaves out is the one the agent already has", setting(path))
	case depth == 0 && (!group || opened != '{'):
		return errors.New("it is not a group of settings")
	case !group:
		return nil
	case opened == '[':
		for index := 0; decoder.More(); index++ {
			if err := scanValue(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
		}
	default:
		written := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("it is not a configuration: %v", err)
			}
			name, named := key.(string)
			if !named {
				return errors.New("it is not a configuration")
			}
			if written[name] {
				return fmt.Errorf("%s is set twice", setting(join(path, name)))
			}
			written[name] = true
			if err := scanValue(decoder, join(path, name), depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("it is not a configuration: %v", err)
	}
	return nil
}

func (c *Config) validate() error {
	transport, spool := c.Transport.validate(), c.Spool.validate()
	found := slices.Concat(
		c.Identity.validate(),
		c.Server.validate(),
		transport,
		spool,
		c.Modules.validate(),
		c.Resources.validate(),
		c.Logging.validate(),
		c.Updates.validate(),
	)
	if state := c.Identity.StateDirectory; filepath.IsAbs(state) {
		for _, path := range c.Modules[watcher].Paths {
			if path == state || strings.HasPrefix(path, state+string(filepath.Separator)) {
				found = append(found, fmt.Errorf("modules.%s.paths names %s, which is within identity.state_directory, the installation the agent writes itself", watcher, secrets.Shown(path)))
			}
		}
	}
	if len(transport) == 0 && len(spool) == 0 && c.Spool.MaxBytes < batchesSpooled*c.Transport.MaxBatchBytes {
		found = append(found, fmt.Errorf("spool.max_bytes is %s, and a spool holds %d batches of transport.max_batch_bytes, %s, so records keep arriving while one is on its way",
			c.Spool.MaxBytes, batchesSpooled, c.Transport.MaxBatchBytes))
	}
	if len(found) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(found...))
	}
	return nil
}

func (i *Identity) validate() []error {
	return problems(
		absolute("identity.state_directory", i.StateDirectory,
			"the directory the agent keeps its installation in", "/var/lib/seagull-agent"),
		chosen("identity.key_provider", i.KeyProvider, providers, "keeps keys with"),
		duration("identity.key_lifetime", i.KeyLifetime, Duration(time.Hour), Duration(8760*time.Hour)),
	)
}

func (s *Server) validate() []error {
	var found []error
	for _, endpoint := range []struct {
		name  string
		value *string
	}{{name: "server.ingest_url", value: &s.IngestURL}, {name: "server.renewal_url", value: &s.RenewalURL}} {
		reached, err := address(endpoint.name, *endpoint.value)
		if err != nil {
			found = append(found, err)
			continue
		}
		*endpoint.value = reached
	}
	if _, err := bundle("server.trust_bundle", s.TrustBundle); err != nil {
		found = append(found, err)
	}
	return found
}

func (t *Transport) validate() []error {
	found := problems(
		duration("transport.connect_timeout", t.ConnectTimeout, Duration(time.Second), Duration(time.Minute)),
		duration("transport.request_timeout", t.RequestTimeout, Duration(5*time.Second), Duration(10*time.Minute)),
		size("transport.max_batch_bytes", t.MaxBatchBytes, 64<<10, 8<<20),
		count("transport.max_events_per_batch", t.MaxEventsPerBatch, 1, 1000),
		count("transport.max_inventory_records_per_batch", t.MaxInventoryRecordsPerBatch, 1, 64),
		size("transport.max_response_bytes", t.MaxResponseBytes, 4<<10, 1<<20),
		size("transport.max_upload_bytes_per_second", t.MaxUploadBytesPerSecond, 64<<10, 1<<30),
	)
	if len(found) > 0 {
		return found
	}
	sending := time.Duration(float64(t.MaxBatchBytes) / float64(t.MaxUploadBytesPerSecond) * float64(time.Second))
	switch {
	case t.RequestTimeout < t.ConnectTimeout:
		found = append(found, fmt.Errorf("transport.request_timeout is %s, and it covers the whole request, so it is never shorter than transport.connect_timeout, %s",
			t.RequestTimeout, t.ConnectTimeout))
	case Duration(sending)+t.ConnectTimeout > t.RequestTimeout:
		found = append(found, fmt.Errorf("transport.request_timeout is %s, and it covers connecting, %s, and sending a batch of transport.max_batch_bytes, %s, at transport.max_upload_bytes_per_second, %s, which takes %s",
			t.RequestTimeout, t.ConnectTimeout, t.MaxBatchBytes, t.MaxUploadBytesPerSecond, Duration(sending.Round(time.Second))))
	}
	return found
}

func (s *Spool) validate() []error {
	return problems(
		size("spool.max_bytes", s.MaxBytes, 16<<20, 64<<30),
		duration("spool.max_age", s.MaxAge, Duration(time.Hour), Duration(720*time.Hour)),
	)
}

func (m Modules) validate() []error {
	var found []error
	for _, name := range slices.Sorted(maps.Keys(m)) {
		held := m[name]
		fallback, takesStock := periodic[name]
		switch {
		case !slices.Contains(collectors, name):
			found = append(found, fmt.Errorf("modules.%s is configured, and this build collects with %s", secrets.Bounded(name), strings.Join(collectors, ", ")))
			continue
		case name != watcher && (held.Paths != nil || held.Exclude != nil):
			found = append(found, fmt.Errorf("modules.%s names paths, and only the %s collector watches any", name, watcher))
		case name == watcher && held.Paths == nil:
			held.Paths = slices.Clone(watched)
			m[name] = held
		}
		if name == watcher {
			found = append(found, held.scoped()...)
		}
		switch {
		case !takesStock && held.Interval != 0:
			found = append(found, fmt.Errorf("modules.%s.interval is %s, and the %s collector follows its source rather than take stock every interval", name, held.Interval, name))
		case takesStock:
			if held.Interval == 0 {
				held.Interval = fallback
				m[name] = held
			}
			if err := duration("modules."+name+".interval", held.Interval, Duration(time.Minute), Duration(24*time.Hour)); err != nil {
				found = append(found, err)
			}
		}
	}
	return found
}

func (m Module) scoped() []error {
	var found []error
	switch {
	case len(m.Paths) == 0:
		found = append(found, fmt.Errorf("modules.%s.paths names nothing, and the %s collector watches the paths it is given", watcher, watcher))
	case len(m.Paths) > maxWatchedPaths:
		found = append(found, fmt.Errorf("modules.%s.paths names %d paths, and this agent watches at most %d", watcher, len(m.Paths), maxWatchedPaths))
	}
	for i, path := range m.Paths {
		name := fmt.Sprintf("modules.%s.paths[%d]", watcher, i)
		if err := absolute(name, path, "a file or a directory to watch", "/etc"); err != nil {
			found = append(found, err)
			continue
		}
		switch made := slices.IndexFunc(unwatched, func(held string) bool { return path == held || strings.HasPrefix(path, held+"/") }); {
		case made >= 0:
			found = append(found, fmt.Errorf("%s is %s, within %s, which holds what the kernel or the service makes up for the agent rather than files the host keeps", name, secrets.Shown(path), unwatched[made]))
		case slices.Index(m.Paths, path) < i:
			found = append(found, fmt.Errorf("%s is %s, which the paths name before", name, secrets.Shown(path)))
		}
	}
	if len(m.Exclude) > maxExcluded {
		found = append(found, fmt.Errorf("modules.%s.exclude names %d paths and names, and this agent leaves out at most %d", watcher, len(m.Exclude), maxExcluded))
	}
	for i, excluded := range m.Exclude {
		name := fmt.Sprintf("modules.%s.exclude[%d]", watcher, i)
		if !strings.HasPrefix(excluded, "/") {
			if _, err := filepath.Match(excluded, ""); err != nil || excluded == "" || len(excluded) > maxNameBytes || strings.ContainsRune(excluded, '/') {
				found = append(found, fmt.Errorf("%s is %s, and it is an absolute path or a pattern a name matches, such as %q", name, secrets.Shown(excluded), "*.swp"))
			}
			continue
		}
		if err := absolute(name, excluded, "a file or a directory to leave out", "/etc/machine-id"); err != nil {
			found = append(found, err)
			continue
		}
		switch {
		case slices.Index(m.Exclude, excluded) < i:
			found = append(found, fmt.Errorf("%s is %s, which the exclusions name before", name, secrets.Shown(excluded)))
		case slices.ContainsFunc(m.Paths, func(path string) bool { return path == excluded || strings.HasPrefix(path, excluded+"/") }):
			found = append(found, fmt.Errorf("%s is %s, which leaves out a whole path modules.%s.paths names", name, secrets.Shown(excluded), watcher))
		case !slices.ContainsFunc(m.Paths, func(path string) bool { return strings.HasPrefix(excluded, path+"/") }):
			found = append(found, fmt.Errorf("%s is %s, which is within none of the paths modules.%s.paths names", name, secrets.Shown(excluded), watcher))
		}
	}
	return found
}

func (r *Resources) validate() []error {
	return problems(
		size("resources.memory_limit", r.MemoryLimit, 64<<20, 8<<30),
		count("resources.max_concurrent_scans", r.MaxConcurrentScans, 1, 64),
		size("resources.max_scan_bytes_per_second", r.MaxScanBytesPerSecond, 1<<20, 1<<30),
		count("resources.max_concurrent_uploads", r.MaxConcurrentUploads, 1, 16),
		duration("resources.shutdown_timeout", r.ShutdownTimeout, Duration(time.Second), Duration(5*time.Minute)),
	)
}

func (l *Logging) validate() []error {
	return problems(
		chosen("logging.level", l.Level, slices.Sorted(maps.Keys(levels)), "logs at"),
		chosen("logging.format", l.Format, logFormats, "writes its log as"),
	)
}

func (u *Updates) validate() []error {
	if u.Enabled {
		return []error{errors.New("updates.enabled is true, and this build installs no update")}
	}
	return nil
}

func problems(found ...error) []error {
	return slices.DeleteFunc(found, func(err error) bool { return err == nil })
}

func chosen(name, value string, accepted []string, does string) error {
	if slices.Contains(accepted, value) {
		return nil
	}
	if value == "" {
		return fmt.Errorf("%s is not set, and this agent %s %s", name, does, strings.Join(accepted, ", "))
	}
	return fmt.Errorf("%s is %s, and this agent %s %s", name, secrets.Shown(value), does, strings.Join(accepted, ", "))
}

func size(name string, value, low, high Size) error {
	if value < low || value > high {
		return fmt.Errorf("%s is %s, and this agent takes between %s and %s", name, value, low, high)
	}
	return nil
}

func duration(name string, value, low, high Duration) error {
	if value < low || value > high {
		return fmt.Errorf("%s is %s, and this agent takes between %s and %s", name, value, low, high)
	}
	return nil
}

func count(name string, value, low, high int) error {
	if value < low || value > high {
		return fmt.Errorf("%s is %d, and this agent takes between %d and %d", name, value, low, high)
	}
	return nil
}

func absolute(name, path, what, example string) error {
	switch {
	case path == "":
		return fmt.Errorf("%s is not set, and it names %s", name, what)
	case len(path) > maxPathBytes:
		return fmt.Errorf("%s is longer than %d bytes", name, maxPathBytes)
	case !filepath.IsAbs(path) || filepath.Clean(path) != path:
		return fmt.Errorf("%s is %s, and it is an absolute path with nothing to resolve, such as %q", name, secrets.Shown(path), example)
	case path == string(filepath.Separator):
		return fmt.Errorf("%s is %q, and it names %s, never the root of the filesystem", name, path, what)
	}
	return nil
}

func (s Server) Authorities() ([]*x509.Certificate, error) {
	return bundle("server.trust_bundle", s.TrustBundle)
}

func bundle(name, path string) ([]*x509.Certificate, error) {
	if err := absolute(name, path,
		"the certificates the agent verifies the platform with", "/etc/seagull-agent/platform-ca.pem"); err != nil {
		return nil, err
	}
	described, err := os.Lstat(path)
	named := secrets.Bounded(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s names %s, and there is no such file", name, named)
	case err != nil:
		return nil, fmt.Errorf("%s names %s, which the agent cannot inspect: %s", name, named, secrets.Bounded(err.Error()))
	case !described.Mode().IsRegular():
		return nil, fmt.Errorf("%s names %s, which is not a regular file", name, named)
	}
	if err := files.Trusted(described); err != nil {
		return nil, fmt.Errorf("%s names %s, and it %v: whoever changes it decides which platform the agent trusts", name, named, err)
	}
	content, err := contents(path, described, maxBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("%s names %s, which %v", name, named, err)
	}
	held, err := authorities(content)
	if err != nil {
		return nil, fmt.Errorf("%s names %s, which %v", name, named, err)
	}
	return held, nil
}

func authorities(content []byte) ([]*x509.Certificate, error) {
	var held []*x509.Certificate
	for rest := content; len(bytes.TrimSpace(rest)) > 0; {
		if len(held) == maxCertificates {
			return nil, fmt.Errorf("holds more than %d certificates", maxCertificates)
		}
		block, remainder := pem.Decode(rest)
		switch {
		case block == nil:
			return nil, errors.New("holds something that is not PEM")
		case block.Type != "CERTIFICATE":
			return nil, fmt.Errorf("holds a %s block, and a trust bundle holds certificates", secrets.Shown(block.Type))
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("holds a block that is not a certificate: %s", secrets.Bounded(err.Error()))
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return nil, fmt.Errorf("holds %s, which is not a certificate authority: the agent trusts the authorities that issue the platform's certificates, never one of those certificates, so the platform can replace them",
				secrets.Shown(certificate.Subject.CommonName))
		}
		held = append(held, certificate)
		rest = remainder
	}
	if len(held) == 0 {
		return nil, errors.New("holds no certificate")
	}
	return held, nil
}

func address(name, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s is not set, and it names the listener the agent reaches, such as %q", name, "https://gateway.example:8443")
	}
	if len(raw) > maxPathBytes {
		return "", fmt.Errorf("%s is longer than %d bytes", name, maxPathBytes)
	}
	reached, err := url.Parse(raw)
	switch {
	case err != nil:
		var unparsed *url.Error
		if errors.As(err, &unparsed) {
			err = unparsed.Err
		}
		return "", fmt.Errorf("%s is %s, which is not a URL: %s", name, secrets.Address(raw), secrets.Bounded(err.Error()))
	case reached.Scheme != "https":
		return "", fmt.Errorf("%s is %s, and the agent speaks to the platform over TLS alone", name, secrets.Address(raw))
	case reached.Host == "" || reached.Hostname() == "":
		return "", fmt.Errorf("%s is %s, and it names no host to reach", name, secrets.Address(raw))
	case reached.User != nil:
		return "", fmt.Errorf("%s carries credentials, and the agent authenticates with the key of its installation", name)
	case reached.RawQuery != "" || reached.ForceQuery || reached.Fragment != "":
		return "", fmt.Errorf("%s is %s, and the agent adds what it asks for to the path it is given", name, secrets.Address(raw))
	}
	reached.Path = strings.TrimSuffix(reached.Path, "/")
	segments := strings.Split(strings.TrimPrefix(reached.Path, "/"), "/")
	unresolved := func(segment string) bool { return segment == "" || segment == "." || segment == ".." }
	if reached.Path != "" && (!strings.HasPrefix(reached.Path, "/") || slices.ContainsFunc(segments, unresolved)) {
		return "", fmt.Errorf("%s is %s, and the path it names has nothing to resolve", name, secrets.Address(raw))
	}
	return reached.String(), nil
}

func setting(path string) string {
	if path == "" {
		return "the configuration"
	}
	return secrets.Bounded(path)
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func explain(err error) string {
	var mistyped *json.UnmarshalTypeError
	if errors.As(err, &mistyped) {
		return fmt.Sprintf("%s is %s, and it takes %s", setting(mistyped.Field), shown(mistyped.Value), expected(mistyped.Type))
	}
	if name, unknown := strings.CutPrefix(err.Error(), "json: unknown field "); unknown {
		return fmt.Sprintf("%s is not a setting this agent has", secrets.Bounded(name))
	}
	return fmt.Sprintf("it is not a configuration: %s", secrets.Bounded(err.Error()))
}

func shown(value string) string {
	switch value {
	case "number":
		return "a number"
	case "string":
		return "text"
	case "bool":
		return "true or false"
	case "object":
		return "a group of settings"
	case "array":
		return "a list"
	}
	return secrets.Bounded(value)
}

func expected(held reflect.Type) string {
	switch held {
	case reflect.TypeFor[Size]():
		return `a size in bytes with a binary unit, such as "8MiB"`
	case reflect.TypeFor[Duration]():
		return `a time with a unit, such as "30s"`
	}
	switch held.Kind() {
	case reflect.String:
		return "text"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int64:
		return "a whole number"
	case reflect.Map, reflect.Struct:
		return "a group of settings"
	}
	return held.String()
}

type Size int64

var sizePattern = regexp.MustCompile(`^([0-9]{1,15})(B|KiB|MiB|GiB)$`)

var units = []struct {
	name  string
	scale Size
}{{name: "GiB", scale: 1 << 30}, {name: "MiB", scale: 1 << 20}, {name: "KiB", scale: 1 << 10}, {name: "B", scale: 1}}

func (s Size) String() string {
	for _, unit := range units {
		if s >= unit.scale && s%unit.scale == 0 {
			return strconv.FormatInt(int64(s/unit.scale), 10) + unit.name
		}
	}
	return strconv.FormatInt(int64(s), 10) + "B"
}

func (s Size) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Size) UnmarshalJSON(content []byte) error {
	var written string
	if err := json.Unmarshal(content, &written); err != nil {
		return mistyped[Size](content)
	}
	groups := sizePattern.FindStringSubmatch(written)
	if groups == nil {
		return mistyped[Size](content)
	}
	counted, err := strconv.ParseInt(groups[1], 10, 64)
	scale := Size(1)
	for _, unit := range units {
		if unit.name == groups[2] {
			scale = unit.scale
		}
	}
	if err != nil || counted > int64(math.MaxInt64/scale) {
		return mistyped[Size](content)
	}
	*s = Size(counted) * scale
	return nil
}

type Duration time.Duration

func (d Duration) String() string {
	switch value := time.Duration(d); {
	case value != 0 && value%time.Hour == 0:
		return strconv.FormatInt(int64(value/time.Hour), 10) + "h"
	case value != 0 && value%time.Minute == 0:
		return strconv.FormatInt(int64(value/time.Minute), 10) + "m"
	case value%time.Second == 0:
		return strconv.FormatInt(int64(value/time.Second), 10) + "s"
	default:
		return value.String()
	}
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(content []byte) error {
	var written string
	if err := json.Unmarshal(content, &written); err != nil {
		return mistyped[Duration](content)
	}
	parsed, err := time.ParseDuration(written)
	if err != nil {
		return mistyped[Duration](content)
	}
	*d = Duration(parsed)
	return nil
}

// The decoder names the setting a value belongs to only when the type it
// refuses is one it knows, so a size and a time report themselves as one.
func mistyped[T any](content []byte) error {
	return &json.UnmarshalTypeError{Value: string(content), Type: reflect.TypeFor[T]()}
}
