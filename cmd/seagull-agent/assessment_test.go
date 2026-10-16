package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

// The checks come with the signed policy and nowhere else: the agent assesses
// its host as soon as it applies one that asks for them, answers a check it
// cannot read as unsupported, and keeps what it found in the spool.
func TestAnAgentAssessesItsHostAgainstTheChecksOfThePolicyItAppliesAndAdmitsWhatItFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent assesses linux hosts")
	}
	path, state, platform, key := policied(t)
	tomorrow := &assessmentv1.Check{CheckId: "from-tomorrow"}
	tomorrow.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), []byte{0x08, 0x01}))
	checks := []*assessmentv1.Check{
		{CheckId: "etc", Test: &assessmentv1.Check_File{File: &assessmentv1.FileTest{Path: "/etc", Kind: assessmentv1.FileTest_KIND_DIRECTORY}}},
		{CheckId: "no-such-group", Test: &assessmentv1.Check_Account{Account: &assessmentv1.AccountTest{
			Rule: assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS, Group: "seagull-no-such-group",
		}}},
		tomorrow,
	}
	platform.hand(sealedPolicy(t, revision(2, &policyv1.Settings{
		Modules:    []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_ASSESSMENT, Collection: policyv1.Collection_COLLECTION_ENABLED}},
		Assessment: &assessmentv1.Checklist{Checks: checks},
	}, "web-01"), key))

	entries, stop := running(t, path)
	await(t, entries, "policy_applied")
	admitted := await(t, entries, "assessment_admitted")
	if admitted["policy_id"] != "linux-web" || admitted["revision"] != float64(2) || admitted["checks"] != float64(3) || admitted["because"] != "first" ||
		admitted["passed"] != float64(1) || admitted["unsupported"] != float64(1) || admitted["not_applicable"] != float64(1) {
		t.Fatalf("the agent admitted %v", admitted)
	}
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}

	root, err := os.OpenRoot(filepath.Join(state, spoolDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	kept, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	held, err := kept.Read(spool.Assessments, 1, 16, 64<<20)
	if err != nil || len(held) != 1 {
		t.Fatalf("the spool holds %d assessments: %v", len(held), err)
	}
	assessed := &assessmentv1.Assessment{}
	if err := proto.Unmarshal(held[0].Payload, assessed); err != nil || assessed.GetAssessmentId() != held[0].ID {
		t.Fatalf("the spool holds %v: %v", assessed, err)
	}
	var found []string
	for _, result := range assessed.GetResults() {
		found = append(found, fmt.Sprintf("%s %s", result.GetCheckId(), result.GetOutcome()))
	}
	if strings.Join(found, ", ") != "etc OUTCOME_PASS, no-such-group OUTCOME_NOT_APPLICABLE, from-tomorrow OUTCOME_UNSUPPORTED" {
		t.Fatalf("the assessment answers %v", found)
	}
}
