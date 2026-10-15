//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	assessDropIn   = "/etc/ssh/sshd_config.d/10-seagull-native-assess.conf"
	privateDropIn  = "/etc/ssh/sshd_config.d/20-seagull-native-private.conf"
	assessModprobe = "/etc/modprobe.d/seagull-native-assess.conf"
	assessPrivate  = "/etc/seagull-native-assess"
	assessGroup    = "seagull-native-assess"
	assessMember   = "seagull-native-member"
)

var (
	pass         = assessmentv1.Outcome_OUTCOME_PASS
	fail         = assessmentv1.Outcome_OUTCOME_FAIL
	erred        = assessmentv1.Outcome_OUTCOME_ERROR
	unsupported  = assessmentv1.Outcome_OUTCOME_UNSUPPORTED
	inapplicable = assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE
)

type assessed struct {
	test     any
	outcome  assessmentv1.Outcome
	evidence string
}

// What the gate asks the agent to check of this host, and what each check
// finds here: one of every outcome the contract has, read through the sandbox
// the service runs the agent in.
func checklist() ([]string, map[string]assessed) {
	required, forbidden := assessmentv1.Presence_PRESENCE_REQUIRED, assessmentv1.Presence_PRESENCE_FORBIDDEN
	logins := func(name string) *assessmentv1.DirectiveTest {
		return &assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS, Name: name}
	}
	server := func(name string, allowed ...string) *assessmentv1.DirectiveTest {
		return &assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: name, Allowed: allowed}
	}
	maxDays, umask, rootLogin := logins("PASS_MAX_DAYS"), logins("UMASK"), server("PermitRootLogin", "no", "prohibit-password")
	maxDays.AtMost, umask.AtLeast, rootLogin.Assumed = proto.Int64(365), proto.Int64(0o22), "prohibit-password"
	order := []string{"shadow-permissions", "passwd-private", "root-home", "hosts-equiv", "private-file", "superuser", "assess-group-empty", "aslr",
		"no-such-parameter", "cramfs", "usb-storage", "ssh-server", "telnetd", "journald", "rsync", "password-auth", "root-login", "allow-users",
		"pass-max-days", "umask", "from-tomorrow"}
	return order, map[string]assessed{
		"shadow-permissions": {&assessmentv1.FileTest{Path: "/etc/shadow", UserId: proto.Uint32(0), Permissions: proto.Uint32(0o640)}, pass, "/etc/shadow is a regular file owned by 0:"},
		"passwd-private":     {&assessmentv1.FileTest{Path: "/etc/passwd", Permissions: proto.Uint32(0o600)}, fail, "its permissions go beyond 0600"},
		"root-home":          {&assessmentv1.FileTest{Path: "/root", Kind: assessmentv1.FileTest_KIND_DIRECTORY}, erred, "the agent's service hides /root from it"},
		"hosts-equiv":        {&assessmentv1.FileTest{Path: "/etc/hosts.equiv", Presence: forbidden}, pass, "/etc/hosts.equiv is not there"},
		"private-file":       {&assessmentv1.FileTest{Path: assessPrivate + "/secret", Permissions: proto.Uint32(0o600)}, erred, assessPrivate + " cannot be searched"},
		"superuser":          {&assessmentv1.AccountTest{Rule: assessmentv1.AccountTest_RULE_ONLY_ROOT_HAS_USER_ID_0}, pass, "no account but root"},
		"assess-group-empty": {&assessmentv1.AccountTest{Rule: assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS, Group: assessGroup}, fail, "has members " + assessMember},
		"aslr":               {&assessmentv1.KernelParameterTest{Name: "kernel.randomize_va_space", Allowed: []string{"2"}}, pass, `kernel.randomize_va_space is "2"`},
		"no-such-parameter":  {&assessmentv1.KernelParameterTest{Name: "kernel.seagull_no_such_parameter", Allowed: []string{"1"}}, inapplicable, "the kernel has no parameter"},
		"cramfs":             {&assessmentv1.KernelModuleTest{Name: "cramfs", Loaded: forbidden, Disabled: true}, pass, assessModprobe + " line 1 has modprobe run \"/bin/false\" for it"},
		"usb-storage":        {&assessmentv1.KernelModuleTest{Name: "usb-storage", Disabled: true}, fail, "keeps usb-storage out"},
		"ssh-server":         {&assessmentv1.PackageTest{Name: "openssh-server", Presence: required}, pass, "openssh-server "},
		"telnetd":            {&assessmentv1.PackageTest{Name: "telnetd", Presence: forbidden}, pass, "telnetd is not installed"},
		"journald":           {&assessmentv1.ServiceTest{Unit: "systemd-journald.service", Activity: assessmentv1.ServiceTest_ACTIVITY_ACTIVE}, pass, "and active"},
		"rsync":              {&assessmentv1.ServiceTest{Unit: "rsync.service", Startup: assessmentv1.ServiceTest_STARTUP_DISABLED}, pass, "rsync.service"},
		"password-auth":      {server("PasswordAuthentication", "no"), fail, `"yes" at ` + assessDropIn + " line 1"},
		"root-login":         {rootLogin, fail, `"yes" in a Match block for User ` + assessMember},
		"allow-users":        {server("AllowUsers", "admin"), unsupported, "sshd gathers AllowUsers"},
		"pass-max-days":      {maxDays, fail, "above 365"},
		"umask":              {umask, pass, `UMASK is "022"`},
		"from-tomorrow":      {nil, unsupported, "newer than this agent reads"},
	}
}

func checks(order []string, held map[string]assessed) []*assessmentv1.Check {
	var made []*assessmentv1.Check
	for _, id := range order {
		check := &assessmentv1.Check{CheckId: id, Title: "the gate's " + id}
		switch test := held[id].test.(type) {
		case *assessmentv1.FileTest:
			check.Test = &assessmentv1.Check_File{File: test}
		case *assessmentv1.AccountTest:
			check.Test = &assessmentv1.Check_Account{Account: test}
		case *assessmentv1.KernelParameterTest:
			check.Test = &assessmentv1.Check_KernelParameter{KernelParameter: test}
		case *assessmentv1.KernelModuleTest:
			check.Test = &assessmentv1.Check_KernelModule{KernelModule: test}
		case *assessmentv1.PackageTest:
			check.Test = &assessmentv1.Check_Package{Package: test}
		case *assessmentv1.ServiceTest:
			check.Test = &assessmentv1.Check_Service{Service: test}
		case *assessmentv1.DirectiveTest:
			check.Test = &assessmentv1.Check_Directive{Directive: test}
		default:
			check.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), []byte{0x08, 0x01}))
		}
		made = append(made, check)
	}
	return made
}

// An operator signs the checks the agent runs into its policy; the agent runs
// them against its host through the sandbox the service puts it in, answers a
// check it cannot read or cannot see through as such, admits what it found,
// and assesses again as soon as it is handed a newer policy.
func (g *gate) assess(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the signer: %v", err)
	}
	place(t, signersPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	place(t, assessDropIn, []byte("PasswordAuthentication yes\nMatch User "+assessMember+"\n    PermitRootLogin yes\n"))
	if err := os.MkdirAll(filepath.Dir(assessModprobe), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(assessModprobe), err)
	}
	place(t, assessModprobe, []byte("install cramfs /bin/false\nblacklist cramfs\n"))
	if err := os.MkdirAll(assessPrivate, 0o700); err != nil {
		t.Fatalf("create %s: %v", assessPrivate, err)
	}
	place(t, filepath.Join(assessPrivate, "secret"), []byte("held by root\n"))
	if err := os.Chmod(assessPrivate, 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, "groupadd", assessGroup)
	run(t, "useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", assessGroup, assessMember)
	t.Cleanup(func() {
		for _, left := range []string{assessDropIn, privateDropIn, assessModprobe} {
			os.Remove(left)
		}
		os.RemoveAll(assessPrivate)
		exec.Command("userdel", assessMember).Run()
		exec.Command("groupdel", assessGroup).Run()
	})

	order, expected := checklist()
	asked := &policyv1.Settings{
		Modules:    []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_ASSESSMENT, Collection: policyv1.Collection_COLLECTION_ENABLED}},
		Assessment: &assessmentv1.Checklist{Checks: checks(order, expected)},
	}
	first := sealPolicy(t, 3, asked, key)
	g.platform.handed.Store(&first)
	g.signers = signersPath
	g.write(t)
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)

	if applied := await(t, g.invocation, "policy_applied", 30*time.Second); applied["revision"] != float64(3) {
		t.Fatalf("the agent applied %v", applied)
	}
	admitted := g.admitted(t, 3, time.Minute)
	if admitted["revision"] != float64(3) || admitted["checks"] != float64(len(order)) || admitted["because"] != "first" {
		t.Fatalf("the agent admitted %v", admitted)
	}
	found := g.assessed(t, 1)
	judge(t, found[0], 3, order, expected)
	owns(t, filepath.Join(state, "collection", "assessment.json"), g.uid, g.gid, 0o600)
	g.statusSays(t, true, "\nmodule assessment: running", fmt.Sprintf("ran the %d checks of revision 3 of gate-servers", len(order)))

	if err := os.WriteFile(privateDropIn, []byte("PermitRootLogin no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privateDropIn, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, unread := range []string{"password-auth", "root-login"} {
		held := expected[unread]
		held.outcome, held.evidence = erred, privateDropIn+": a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets the agent read it"
		expected[unread] = held
	}
	second := sealPolicy(t, 4, asked, key)
	g.platform.handed.Store(&second)
	again := g.admitted(t, 4, 3*time.Minute)
	if again["revision"] != float64(4) || again["because"] != "changed" || again["errors"] != float64(4) {
		t.Fatalf("after a newer policy the agent admitted %v", again)
	}
	found = g.assessed(t, 2)
	judge(t, found[1], 4, order, expected)
	g.statusSays(t, true, fmt.Sprintf("ran the %d checks of revision 4 of gate-servers", len(order)))

	run(t, "systemctl", "stop", unit)
	if *evidence != "" {
		g.recordAssessments(t, [][]byte{first, second}, key)
	}
	g.signers = ""
	g.platform.handed.Store(nil)
	g.write(t)
}

func (g *gate) admitted(t *testing.T, revision uint64, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		for _, entry := range journal(t, g.invocation) {
			if entry["msg"] == "assessment_admitted" && entry["revision"] == float64(revision) {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent admitted no assessment of revision %d within %s:\n%s", revision, within,
				answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (g *gate) assessed(t *testing.T, count int) []*assessmentv1.Assessment {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		found, _ := g.platform.assessments()
		if len(found) >= count {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("the platform holds %d assessments, want %d:\n%s", len(found), count,
				answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func judge(t *testing.T, found *assessmentv1.Assessment, revision uint64, order []string, expected map[string]assessed) {
	t.Helper()
	results := found.GetResults()
	if found.GetPolicyId() != "gate-servers" || found.GetPolicyRevision() != revision || len(results) != len(order) {
		t.Fatalf("the platform holds an assessment of revision %d answering %d checks: %v", found.GetPolicyRevision(), len(results), found)
	}
	for index, result := range results {
		want := expected[order[index]]
		if result.GetCheckId() != order[index] || result.GetOutcome() != want.outcome || !strings.Contains(result.GetEvidence(), want.evidence) {
			t.Errorf("%s was answered %s %q, want %s with %q", order[index], result.GetOutcome(), result.GetEvidence(), want.outcome, want.evidence)
		}
	}
}

// recordAssessments writes the policies the gate signed, the key that verifies
// them and every assessment batch the platform took, for the platform's own
// recordings to be made of.
func (g *gate) recordAssessments(t *testing.T, policies [][]byte, key *ecdsa.PrivateKey) {
	t.Helper()
	directory := filepath.Join(*evidence, "assessment")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "policy-signers.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	type told struct {
		Batch      string            `json:"batch"`
		ID         string            `json:"assessment_id"`
		Revision   uint64            `json:"policy_revision"`
		AssessedAt time.Time         `json:"assessed_at"`
		Outcomes   map[string]string `json:"outcomes"`
	}
	scenario := struct {
		RecordedAt     time.Time `json:"recorded_at"`
		InstallationID string    `json:"installation_id"`
		AgentID        string    `json:"agent_id"`
		Policies       []string  `json:"policies"`
		Assessments    []told    `json:"assessments"`
	}{RecordedAt: time.Now().UTC(), InstallationID: g.installation, AgentID: agentID}
	for index, envelope := range policies {
		name := fmt.Sprintf("policy-%03d.pb", index)
		if err := os.WriteFile(filepath.Join(directory, name), envelope, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		scenario.Policies = append(scenario.Policies, name)
	}
	_, batches := g.platform.assessments()
	for index, batch := range batches {
		var decoded assessmentv1.AssessmentBatch
		if err := proto.Unmarshal(batch, &decoded); err != nil {
			t.Fatalf("decode assessment batch %d: %v", index, err)
		}
		name := fmt.Sprintf("batch-%03d.pb", index)
		if err := os.WriteFile(filepath.Join(directory, name), batch, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		for _, carried := range decoded.GetAssessments() {
			outcomes := map[string]string{}
			for _, result := range carried.GetResults() {
				outcomes[result.GetCheckId()] = result.GetOutcome().String()
			}
			scenario.Assessments = append(scenario.Assessments, told{Batch: name, ID: carried.GetAssessmentId(), Revision: carried.GetPolicyRevision(),
				AssessedAt: carried.GetAssessedAt().AsTime(), Outcomes: outcomes})
		}
	}
	encoded, err := json.MarshalIndent(scenario, "", "  ")
	if err != nil {
		t.Fatalf("encode the scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "scenario.json"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write the scenario: %v", err)
	}
}
