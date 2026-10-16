package assessment

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/kmod"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/logindefs"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/metadata"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sshd"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sysctl"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// A host the test describes whole, which counts how often each source is read
// and fails a source it is told to.
type fakeHost struct {
	nodes      map[string]metadata.Node
	hidden     []string
	denied     []string
	database   accounts.Database
	parameters map[string]string
	loaded     map[string]kmod.State
	install    []kmod.Rule
	blacklist  []kmod.Rule
	packages   []dpkg.Package
	units      map[string]services.Unit
	sshd       map[string][]sshd.Setting
	logins     map[string]logindefs.Setting
	failing    map[string]error
	reads      map[string]int
}

func newHost() *fakeHost {
	return &fakeHost{
		nodes: map[string]metadata.Node{
			"/etc":                {Kind: metadata.Directory, Permissions: 0o755},
			"/etc/shadow":         {Kind: metadata.Regular, Group: 42, Permissions: 0o640},
			"/etc/passwd":         {Kind: metadata.Regular, Permissions: 0o644},
			"/etc/crontab":        {Kind: metadata.Regular, Permissions: 0o644},
			"/etc/mtab":           {Kind: metadata.Symlink, Permissions: 0o777},
			"/usr/bin/sudo":       {Kind: metadata.Regular, Permissions: 0o4755},
			"/boot/grub/grub.cfg": {Kind: metadata.Regular, Permissions: 0o444},
		},
		hidden: []string{"/root", "/home"},
		denied: []string{"/etc/ssl/private"},
		database: accounts.Database{
			Accounts: []accounts.Account{{Name: "root"}, {Name: "daemon", UID: 1, GID: 1}, {Name: "alice", UID: 1000, GID: 1000}, {Name: "bob", UID: 1001, GID: 1001}},
			Groups:   []accounts.Group{{Name: "root"}, {Name: "daemon", GID: 1}, {Name: "shadow", GID: 42}, {Name: "alice", GID: 1000}, {Name: "bob", GID: 1001}},
		},
		parameters: map[string]string{
			"net.ipv4.ip_forward":          "0",
			"kernel.randomize_va_space":    "2",
			"net.ipv4.ip_local_port_range": "32768 60999",
			"kernel.yama.ptrace_scope":     "1",
		},
		loaded:    map[string]kmod.State{"tls": kmod.Loaded, "vt": kmod.BuiltIn},
		install:   []kmod.Rule{{Module: "cramfs", Command: "/bin/false", File: "/etc/modprobe.d/cramfs.conf", Line: 1}, {Module: "usb_storage", Command: "/sbin/modprobe --ignore-install usb_storage", File: "/etc/modprobe.d/usb.conf", Line: 2}},
		blacklist: []kmod.Rule{{Module: "cramfs", File: "/etc/modprobe.d/cramfs.conf", Line: 2}},
		packages:  []dpkg.Package{{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13", Architecture: "amd64"}, {Name: "libc6", Version: "2.39", Architecture: "amd64"}, {Name: "libc6", Version: "2.39", Architecture: "i386"}},
		units: map[string]services.Unit{
			"ssh.service":              {ID: "ssh.service", Load: "loaded", Active: "active", File: "enabled"},
			"sshd.service":             {ID: "ssh.service", Load: "loaded", Active: "active", File: "enabled"},
			"cron.service":             {ID: "cron.service", Load: "loaded", Active: "active", File: "enabled"},
			"rsync.service":            {ID: "rsync.service", Load: "loaded", Active: "inactive", File: "disabled"},
			"telnet.socket":            {ID: "telnet.socket", Load: "masked", Active: "inactive", File: "masked"},
			"systemd-journald.service": {ID: "systemd-journald.service", Load: "loaded", Active: "active", File: "static"},
		},
		sshd: map[string][]sshd.Setting{
			"permitrootlogin":        {{Value: "no", File: "/etc/ssh/sshd_config.d/10-hardening.conf", Line: 1}, {Value: "yes", File: "/etc/ssh/sshd_config", Line: 33}},
			"passwordauthentication": {{Value: "no", File: "/etc/ssh/sshd_config", Line: 57}, {Value: "yes", File: "/etc/ssh/sshd_config", Line: 120, Match: "Address 10.0.0.0/8"}},
			"maxauthtries":           {{Value: "4", File: "/etc/ssh/sshd_config", Line: 40}},
			"x11forwarding":          {{Value: "yes", File: "/etc/ssh/sshd_config", Line: 90}},
		},
		logins: map[string]logindefs.Setting{
			"PASS_MAX_DAYS":  {Value: "99999", File: "/etc/login.defs", Line: 160},
			"UMASK":          {Value: "027", File: "/etc/login.defs", Line: 151},
			"ENCRYPT_METHOD": {Value: "SHA512", File: "/etc/login.defs", Line: 330},
		},
		failing: map[string]error{},
		reads:   map[string]int{},
	}
}

func (h *fakeHost) read(source string) error {
	h.reads[source]++
	return h.failing[source]
}

func (h *fakeHost) Hostname() (string, error) { return "web-01", nil }

func (h *fakeHost) Describe(name string) (metadata.Node, error) {
	if err := h.read("describe"); err != nil {
		return metadata.Node{}, err
	}
	for _, hiding := range h.hidden {
		if name == hiding || strings.HasPrefix(name, hiding+"/") {
			return metadata.Node{}, fmt.Errorf("%w: %s", metadata.ErrHidden, hiding)
		}
	}
	for _, refusing := range h.denied {
		if strings.HasPrefix(name, refusing+"/") {
			return metadata.Node{}, fmt.Errorf("%w: %s cannot be searched", metadata.ErrDenied, refusing)
		}
	}
	node, found := h.nodes[name]
	if !found {
		return metadata.Node{}, fmt.Errorf("%w: %s", metadata.ErrAbsent, name)
	}
	return node, nil
}

func (h *fakeHost) Accounts() (accounts.Database, error) { return h.database, h.read("accounts") }

func (h *fakeHost) Parameter(name string) (string, error) {
	if err := h.read("parameters"); err != nil {
		return "", err
	}
	value, found := h.parameters[name]
	if !found {
		return "", fmt.Errorf("%w: %s", sysctl.ErrAbsent, name)
	}
	return value, nil
}

func (h *fakeHost) Modules() (Modules, error) { return loadedModules(h.loaded), h.read("modules") }

func (h *fakeHost) Modprobe() (Modprobe, error) {
	return rules{install: h.install, blacklist: h.blacklist}, h.read("modprobe")
}

func (h *fakeHost) Packages(context.Context) ([]dpkg.Package, error) {
	return h.packages, h.read("packages")
}

func (h *fakeHost) Units(_ context.Context, names []string) ([]services.Unit, error) {
	if err := h.read("units"); err != nil {
		return nil, err
	}
	var shown []services.Unit
	for _, name := range names {
		unit, found := h.units[name]
		if !found {
			unit = services.Unit{ID: name, Load: "not-found", Active: "inactive"}
		}
		unit.Asked = name
		shown = append(shown, unit)
	}
	return shown, nil
}

func (h *fakeHost) SSHD() (Directives, error) { return directives(h.sshd), h.read("sshd") }

func (h *fakeHost) LoginDefs() (map[string]logindefs.Setting, error) {
	return h.logins, h.read("logins")
}

type loadedModules map[string]kmod.State

func (l loadedModules) State(name string) (kmod.State, error) {
	normal, err := kmod.Name(name)
	if err != nil {
		return kmod.Absent, err
	}
	return l[normal], nil
}

type rules struct{ install, blacklist []kmod.Rule }

func (r rules) Install(name string) (kmod.Rule, bool) {
	normal, _ := kmod.Name(name)
	index := slices.IndexFunc(r.install, func(rule kmod.Rule) bool {
		matched, _ := path.Match(rule.Module, normal)
		return matched
	})
	if index < 0 {
		return kmod.Rule{}, false
	}
	return r.install[index], true
}

func (r rules) Blacklisted(name string) (kmod.Rule, bool) {
	normal, _ := kmod.Name(name)
	index := slices.IndexFunc(r.blacklist, func(rule kmod.Rule) bool { return rule.Module == normal })
	if index < 0 {
		return kmod.Rule{}, false
	}
	return r.blacklist[index], true
}

type directives map[string][]sshd.Setting

func (d directives) Settings(keyword string) []sshd.Setting { return d[strings.ToLower(keyword)] }

func checked(id string, test any) *assessmentv1.Check {
	check := &assessmentv1.Check{CheckId: id}
	switch held := test.(type) {
	case *assessmentv1.FileTest:
		check.Test = &assessmentv1.Check_File{File: held}
	case *assessmentv1.AccountTest:
		check.Test = &assessmentv1.Check_Account{Account: held}
	case *assessmentv1.KernelParameterTest:
		check.Test = &assessmentv1.Check_KernelParameter{KernelParameter: held}
	case *assessmentv1.KernelModuleTest:
		check.Test = &assessmentv1.Check_KernelModule{KernelModule: held}
	case *assessmentv1.PackageTest:
		check.Test = &assessmentv1.Check_Package{Package: held}
	case *assessmentv1.ServiceTest:
		check.Test = &assessmentv1.Check_Service{Service: held}
	case *assessmentv1.DirectiveTest:
		check.Test = &assessmentv1.Check_Directive{Directive: held}
	}
	return check
}

type answered struct {
	outcome  assessmentv1.Outcome
	evidence string
}

// expect runs every check against the host in one round and holds each
// result to its outcome and to a part of its evidence.
func expect(t *testing.T, host *fakeHost, cases map[string]struct {
	test any
	want answered
}) {
	t.Helper()
	var checks []*assessmentv1.Check
	for name, one := range cases {
		checks = append(checks, checked(strings.ReplaceAll(name, " ", "-"), one.test))
	}
	round := newRound(t.Context(), host, checks)
	for _, check := range checks {
		name := strings.ReplaceAll(check.GetCheckId(), "-", " ")
		want := cases[name].want
		got := round.answer(check)
		if got.GetCheckId() != check.GetCheckId() || got.GetOutcome() != want.outcome || !strings.Contains(got.GetEvidence(), want.evidence) {
			t.Errorf("%s was answered %s %q, want %s with %q", name, got.GetOutcome(), got.GetEvidence(), want.outcome, want.evidence)
		}
	}
}

var (
	pass         = assessmentv1.Outcome_OUTCOME_PASS
	fail         = assessmentv1.Outcome_OUTCOME_FAIL
	erred        = assessmentv1.Outcome_OUTCOME_ERROR
	unsupported  = assessmentv1.Outcome_OUTCOME_UNSUPPORTED
	inapplicable = assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE
	required     = assessmentv1.Presence_PRESENCE_REQUIRED
	forbidden    = assessmentv1.Presence_PRESENCE_FORBIDDEN
)

func cloned[T proto.Message](message T) T { return proto.Clone(message).(T) }
