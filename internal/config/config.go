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
	maxShownBytes   = 48
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
	collectors []string
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
	StateDirectory string `json:"state_directory"`
	KeyProvider    string `json:"key_provider"`
}

type Server struct {
	IngestURL   string `json:"ingest_url"`
	RenewalURL  string `json:"renewal_url"`
	TrustBundle string `json:"trust_bundle"`
}

type Transport struct {
	ConnectTimeout   Duration `json:"connect_timeout"`
	RequestTimeout   Duration `json:"request_timeout"`
	MaxBatchBytes    Size     `json:"max_batch_bytes"`
	MaxResponseBytes Size     `json:"max_response_bytes"`
}

type Spool struct {
	MaxBytes Size     `json:"max_bytes"`
	MaxAge   Duration `json:"max_age"`
}

type Modules map[string]Module

type Module struct {
	Enabled bool `json:"enabled"`
}

type Resources struct {
	MemoryLimit              Size     `json:"memory_limit"`
	MaxConcurrentCollections int      `json:"max_concurrent_collections"`
	MaxConcurrentUploads     int      `json:"max_concurrent_uploads"`
	ShutdownTimeout          Duration `json:"shutdown_timeout"`
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
		Identity: Identity{KeyProvider: KeysInFiles},
		Transport: Transport{
			ConnectTimeout:   Duration(10 * time.Second),
			RequestTimeout:   Duration(30 * time.Second),
			MaxBatchBytes:    4 << 20,
			MaxResponseBytes: 64 << 10,
		},
		Spool:   Spool{MaxBytes: 512 << 20, MaxAge: Duration(72 * time.Hour)},
		Modules: Modules{},
		Resources: Resources{
			MemoryLimit:              256 << 20,
			MaxConcurrentCollections: 2,
			MaxConcurrentUploads:     1,
			ShutdownTimeout:          Duration(10 * time.Second),
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
	if err := bundle("server.trust_bundle", s.TrustBundle); err != nil {
		found = append(found, err)
	}
	return found
}

func (t *Transport) validate() []error {
	found := problems(
		duration("transport.connect_timeout", t.ConnectTimeout, Duration(time.Second), Duration(time.Minute)),
		duration("transport.request_timeout", t.RequestTimeout, Duration(5*time.Second), Duration(10*time.Minute)),
		size("transport.max_batch_bytes", t.MaxBatchBytes, 64<<10, 8<<20),
		size("transport.max_response_bytes", t.MaxResponseBytes, 4<<10, 1<<20),
	)
	if len(found) == 0 && t.RequestTimeout < t.ConnectTimeout {
		found = append(found, fmt.Errorf("transport.request_timeout is %s, and it covers the whole request, so it is never shorter than transport.connect_timeout, %s",
			t.RequestTimeout, t.ConnectTimeout))
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
		switch {
		case len(collectors) == 0:
			found = append(found, fmt.Errorf("modules.%s is configured, and this build has no collector to configure", name))
		case !slices.Contains(collectors, name):
			found = append(found, fmt.Errorf("modules.%s is configured, and this build collects with %s", name, strings.Join(collectors, ", ")))
		}
	}
	return found
}

func (r *Resources) validate() []error {
	return problems(
		size("resources.memory_limit", r.MemoryLimit, 64<<20, 8<<30),
		count("resources.max_concurrent_collections", r.MaxConcurrentCollections, 1, 64),
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
	return fmt.Errorf("%s is %q, and this agent %s %s", name, value, does, strings.Join(accepted, ", "))
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
		return fmt.Errorf("%s is %q, and it is an absolute path with nothing to resolve, such as %q", name, path, example)
	case path == string(filepath.Separator):
		return fmt.Errorf("%s is %q, and it names %s, never the root of the filesystem", name, path, what)
	}
	return nil
}

func bundle(name, path string) error {
	if err := absolute(name, path,
		"the certificates the agent verifies the platform with", "/etc/seagull-agent/platform-ca.pem"); err != nil {
		return err
	}
	described, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s names %s, and there is no such file", name, path)
	case err != nil:
		return fmt.Errorf("%s names %s, which the agent cannot inspect: %v", name, path, err)
	case !described.Mode().IsRegular():
		return fmt.Errorf("%s names %s, which is not a regular file", name, path)
	}
	if err := files.Trusted(described); err != nil {
		return fmt.Errorf("%s names %s, and it %v: whoever changes it decides which platform the agent trusts", name, path, err)
	}
	content, err := contents(path, described, maxBundleBytes)
	if err != nil {
		return fmt.Errorf("%s names %s, which %v", name, path, err)
	}
	if err := authorities(content); err != nil {
		return fmt.Errorf("%s names %s, which %v", name, path, err)
	}
	return nil
}

func authorities(content []byte) error {
	certificates := 0
	for rest := content; len(bytes.TrimSpace(rest)) > 0; certificates++ {
		if certificates == maxCertificates {
			return fmt.Errorf("holds more than %d certificates", maxCertificates)
		}
		block, remainder := pem.Decode(rest)
		switch {
		case block == nil:
			return errors.New("holds something that is not PEM")
		case block.Type != "CERTIFICATE":
			return fmt.Errorf("holds a %q block, and a trust bundle holds certificates", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("holds a block that is not a certificate: %v", err)
		}
		rest = remainder
	}
	if certificates == 0 {
		return errors.New("holds no certificate")
	}
	return nil
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
		return "", fmt.Errorf("%s is %q, which is not a URL: %v", name, raw, err)
	case reached.Scheme != "https":
		return "", fmt.Errorf("%s is %q, and the agent speaks to the platform over TLS alone", name, raw)
	case reached.Host == "" || reached.Hostname() == "":
		return "", fmt.Errorf("%s is %q, and it names no host to reach", name, raw)
	case reached.User != nil:
		return "", fmt.Errorf("%s carries credentials, and the agent authenticates with the key of its installation", name)
	case reached.RawQuery != "" || reached.ForceQuery || reached.Fragment != "":
		return "", fmt.Errorf("%s is %q, and the agent adds what it asks for to the path it is given", name, raw)
	}
	reached.Path = strings.TrimSuffix(reached.Path, "/")
	segments := strings.Split(strings.TrimPrefix(reached.Path, "/"), "/")
	unresolved := func(segment string) bool { return segment == "" || segment == "." || segment == ".." }
	if reached.Path != "" && (!strings.HasPrefix(reached.Path, "/") || slices.ContainsFunc(segments, unresolved)) {
		return "", fmt.Errorf("%s is %q, and the path it names has nothing to resolve", name, raw)
	}
	return reached.String(), nil
}

func setting(path string) string {
	if path == "" {
		return "the configuration"
	}
	return path
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
		return fmt.Sprintf("%s is not a setting this agent has", name)
	}
	return fmt.Sprintf("it is not a configuration: %v", err)
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
	return value
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
	value := string(content)
	if len(value) > maxShownBytes {
		value = value[:maxShownBytes] + "..."
	}
	return &json.UnmarshalTypeError{Value: value, Type: reflect.TypeFor[T]()}
}
