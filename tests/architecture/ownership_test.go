package architecture_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var platforms = []string{"linux", "windows", "darwin"}

const platformAdapters = "internal/platform"

type buildPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Imports    []string
	Deps       []string
	Error      *struct{ Err string }
}

// Each rule names the packages that own a responsibility and what they must
// not depend on to keep it. A transitive rule also holds through every package
// they import, so a collector cannot reach the network through a helper.
type dependencyRule struct {
	packages   string
	exempt     string
	forbidden  []string
	transitive bool
	reason     string
}

var networkPackages = []string{"net/http", "net/rpc", "crypto/tls", "google.golang.org/grpc", "golang.org/x/net/http2"}

var dependencyRules = []dependencyRule{
	{
		exempt:    "cmd/seagull-agent",
		forbidden: []string{modulePath + "/internal/runtime"},
		reason:    "only the composition root decides which components run and when the agent stops",
	},
	{
		packages:   "internal/runtime",
		forbidden:  []string{modulePath, contractsPath},
		transitive: true,
		reason:     "the runtime owns the lifecycle of every component and knows none of them",
	},
	{
		packages:   "internal/modules",
		forbidden:  networkPackages,
		transitive: true,
		reason:     "collectors hand observations to admission; delivery owns requests, connections and TLS",
	},
	{
		packages:   "internal/protocol",
		forbidden:  networkPackages,
		transitive: true,
		reason:     "the protocol speaks in contract terms, the versions the agent writes and the refusals the platform answers with; delivery owns how they travel",
	},
	{
		packages:  "internal/identity",
		forbidden: append([]string{"net"}, networkPackages...),
		reason:    "an installation is who the agent is locally; addresses, interfaces and a server's answer are observations, never where its identity comes from",
	},
}

func (r dependencyRule) violations(pkg buildPackage) []string {
	if !within(pkg.ImportPath, path.Join(modulePath, r.packages)) {
		return nil
	}
	if r.exempt != "" && within(pkg.ImportPath, path.Join(modulePath, r.exempt)) {
		return nil
	}
	dependencies := pkg.Imports
	if r.transitive {
		dependencies = pkg.Deps
	}
	var reached []string
	for _, dependency := range dependencies {
		if slices.ContainsFunc(r.forbidden, func(forbidden string) bool { return within(dependency, forbidden) }) {
			reached = append(reached, dependency)
		}
	}
	return slices.DeleteFunc(slices.Clone(reached), func(dependency string) bool {
		return slices.ContainsFunc(reached, func(other string) bool { return other != dependency && within(dependency, other) })
	})
}

func TestTheOwnershipRulesRecogniseViolations(t *testing.T) {
	ingest := contractsPath + "/gen/go/seagull/ingest/v1"
	cases := []struct {
		name string
		pkg  buildPackage
		want []string
	}{
		{
			name: "a collector sending its own requests",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/modules/auth",
				Imports:    []string{"net/http"},
				Deps:       []string{"crypto/tls", "crypto/tls/internal/fips140tls", "net/http", "net/http/httptrace"},
			},
			want: []string{"crypto/tls", "net/http"},
		},
		{
			name: "a collector reaching TLS through another package",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/modules/auth",
				Imports:    []string{modulePath + "/internal/transport"},
				Deps:       []string{"crypto/tls", modulePath + "/internal/transport"},
			},
			want: []string{"crypto/tls"},
		},
		{
			name: "a collector handing observations to admission",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/modules/auth",
				Imports:    []string{modulePath + "/internal/telemetry"},
				Deps:       []string{ingest, modulePath + "/internal/telemetry", "os"},
			},
		},
		{
			name: "a collector stopping the agent",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/modules/fim",
				Imports:    []string{modulePath + "/internal/runtime"},
				Deps:       []string{modulePath + "/internal/runtime"},
			},
			want: []string{modulePath + "/internal/runtime"},
		},
		{
			name: "the composition root running the agent",
			pkg: buildPackage{
				ImportPath: modulePath + "/cmd/seagull-agent",
				Imports:    []string{modulePath + "/internal/runtime", modulePath + "/internal/transport"},
				Deps:       []string{"crypto/tls", modulePath + "/internal/runtime", modulePath + "/internal/transport"},
			},
		},
		{
			name: "the runtime knowing a component",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/runtime",
				Imports:    []string{modulePath + "/internal/spool", modulePath + "/internal/telemetry"},
				Deps:       []string{modulePath + "/internal/spool", modulePath + "/internal/spool/segment", modulePath + "/internal/telemetry"},
			},
			want: []string{modulePath + "/internal/spool", modulePath + "/internal/telemetry"},
		},
		{
			name: "the runtime knowing a contract",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/runtime",
				Deps:       []string{ingest, "google.golang.org/protobuf/proto"},
			},
			want: []string{ingest},
		},
		{
			name: "the protocol reading a refusal off the HTTP status",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/protocol",
				Imports:    []string{ingest, "net/http"},
				Deps:       []string{"crypto/tls", ingest, "net/http"},
			},
			want: []string{"crypto/tls", "net/http"},
		},
		{
			name: "the protocol reading a refusal off the contracts",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/protocol",
				Imports:    []string{ingest, "google.golang.org/protobuf/reflect/protoreflect"},
				Deps:       []string{ingest, "google.golang.org/protobuf/reflect/protoreflect"},
			},
		},
		{
			name: "the installation named after the machine's network interfaces",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/identity",
				Imports:    []string{"crypto/rand", "net"},
				Deps:       []string{"crypto/rand", "net"},
			},
			want: []string{"net"},
		},
		{
			name: "the installation checking certificates it was issued",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/identity",
				Imports:    []string{"crypto/x509"},
				Deps:       []string{"crypto/x509", "net", "net/url"},
			},
		},
		{
			name: "the runtime on the standard library alone",
			pkg: buildPackage{
				ImportPath: modulePath + "/internal/runtime",
				Imports:    []string{"context", "log/slog"},
				Deps:       []string{"context", "log/slog"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var found []string
			for _, rule := range dependencyRules {
				found = append(found, rule.violations(c.pkg)...)
			}
			if !slices.Equal(found, c.want) {
				t.Fatalf("found %q, want %q", found, c.want)
			}
		})
	}
}

func TestComponentsDependOnlyOnWhatTheirResponsibilityAllows(t *testing.T) {
	root := moduleRoot(t)
	found := map[string][]string{}
	for _, goos := range platforms {
		for _, pkg := range buildGraph(t, root, goos) {
			for _, rule := range dependencyRules {
				for _, dependency := range rule.violations(pkg) {
					violation := fmt.Sprintf("%s depends on %s: %s", pkg.ImportPath, dependency, rule.reason)
					found[violation] = append(found[violation], goos)
				}
			}
		}
	}
	for _, violation := range slices.Sorted(maps.Keys(found)) {
		t.Errorf("%s (built for %s)", violation, strings.Join(found[violation], ", "))
	}
}

func nativeOutsideAdapters(built map[string][]string) []string {
	var found []string
	for name, goos := range built {
		if len(goos) < len(platforms) && !within(name, platformAdapters) {
			found = append(found, name)
		}
	}
	slices.Sort(found)
	return found
}

func TestNativeFilesOutsideAdaptersAreRecognised(t *testing.T) {
	built := map[string][]string{
		"internal/modules/auth/parse.go":          platforms,
		"internal/modules/auth/journal_linux.go":  {"linux"},
		"internal/platform/linux/journal.go":      {"linux"},
		"internal/platform/unix/signals.go":       {"linux", "darwin"},
		"internal/platformer/signals_unix.go":     {"linux", "darwin"},
		"cmd/seagull-agent/service_windows.go":    {"windows"},
		"cmd/seagull-agent/main.go":               platforms,
		"internal/runtime/runtime.go":             platforms,
		"internal/modules/process/procfs_unix.go": {"linux", "darwin"},
	}
	want := []string{
		"cmd/seagull-agent/service_windows.go",
		"internal/modules/auth/journal_linux.go",
		"internal/modules/process/procfs_unix.go",
		"internal/platformer/signals_unix.go",
	}
	if found := nativeOutsideAdapters(built); !slices.Equal(found, want) {
		t.Fatalf("found %q, want %q", found, want)
	}
}

func TestNativeCodeLivesInPlatformAdapters(t *testing.T) {
	root := moduleRoot(t)
	built := map[string][]string{}
	for _, goos := range platforms {
		for _, pkg := range buildGraph(t, root, goos) {
			for _, file := range pkg.GoFiles {
				name := relative(root, filepath.Join(pkg.Dir, file))
				built[name] = append(built[name], goos)
			}
		}
	}
	for _, name := range nativeOutsideAdapters(built) {
		t.Errorf("%s builds only for %s: native access belongs to an adapter under %s",
			name, strings.Join(built[name], ", "), platformAdapters)
	}
}

func buildGraph(t *testing.T, root, goos string) []buildPackage {
	t.Helper()
	output := runWith(t, root, []string{"GOOS=" + goos, "GOARCH=amd64", "CGO_ENABLED=0"},
		"go", "list", "-e", "-json=ImportPath,Dir,GoFiles,Imports,Deps,Error", "./...")
	var packages []buildPackage
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg buildPackage
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			return packages
		}
		if err != nil {
			t.Fatalf("decode the build graph for %s: %v", goos, err)
		}
		if pkg.Error != nil && len(pkg.GoFiles) > 0 {
			t.Fatalf("list %s for %s: %s", pkg.ImportPath, goos, pkg.Error.Err)
		}
		packages = append(packages, pkg)
	}
}
