package architecture_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const githubActions = 15368

var (
	usedAction    = regexp.MustCompile(`(?m)^\s+(?:- )?uses: (\S+)`)
	actionByHash  = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	usedImage     = regexp.MustCompile(`(?m)^\s+container: (\S+)`)
	imageByDigest = regexp.MustCompile(`^golang:(\d+\.\d+\.\d+)-[a-z]+@sha256:[0-9a-f]{64}$`)
	declaredGo    = regexp.MustCompile(`(?m)^toolchain go(\S+)$`)
	jobName       = regexp.MustCompile(`(?m)^    name: (.+)$`)
	waitsOnTag    = regexp.MustCompile(`(?m)^    needs: signature$`)
	readOnly      = regexp.MustCompile(`(?m)^permissions:\n  contents: read\n`)
)

func workflows(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(moduleRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no workflow was found")
	}
	found := map[string]string{}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		found[filepath.Base(file)] = string(content)
	}
	return found
}

func TestEveryActionIsNamedByItsCommit(t *testing.T) {
	for name, content := range workflows(t) {
		for _, used := range usedAction.FindAllStringSubmatch(content, -1) {
			if !actionByHash.MatchString(used[1]) {
				t.Errorf("%s: %s is named by a tag, which its owner can move: name it by its commit", name, used[1])
			}
		}
	}
}

func TestAWorkflowWritesNothingUnlessAJobAsks(t *testing.T) {
	for name, content := range workflows(t) {
		if !readOnly.MatchString(content) {
			t.Errorf("%s grants its jobs more than reading the repository", name)
		}
	}
}

func TestOneToolchainBuildsTheAgent(t *testing.T) {
	module, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	declared := declaredGo.FindSubmatch(module)
	if declared == nil {
		t.Fatal("go.mod names no toolchain")
	}
	images := 0
	for name, content := range workflows(t) {
		if strings.Contains(content, "go-version:") {
			t.Errorf("%s chooses its Go rather than reading it from go.mod", name)
		}
		for _, used := range usedImage.FindAllStringSubmatch(content, -1) {
			images++
			image := imageByDigest.FindStringSubmatch(used[1])
			switch {
			case image == nil:
				t.Errorf("%s: %s is not a golang image named by its digest", name, used[1])
			case image[1] != string(declared[1]):
				t.Errorf("%s builds with go%s and go.mod names go%s", name, image[1], declared[1])
			}
		}
	}
	if images == 0 {
		t.Fatal("no workflow rebuilds the package in a golang image")
	}
}

func TestEveryJobIsRequiredOnMain(t *testing.T) {
	var ruleset struct {
		BypassActors []any `json:"bypass_actors"`
		Rules        []struct {
			Type       string `json:"type"`
			Parameters struct {
				Required []struct {
					Context       string `json:"context"`
					IntegrationID int    `json:"integration_id"`
				} `json:"required_status_checks"`
			} `json:"parameters"`
		} `json:"rules"`
	}
	content, err := os.ReadFile(filepath.Join(moduleRoot(t), ".github", "rulesets", "main.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &ruleset); err != nil {
		t.Fatal(err)
	}
	if len(ruleset.BypassActors) > 0 {
		t.Errorf("%d actors may bypass the rules of main, want none", len(ruleset.BypassActors))
	}

	var required, types []string
	for _, rule := range ruleset.Rules {
		types = append(types, rule.Type)
		for _, check := range rule.Parameters.Required {
			required = append(required, check.Context)
			if check.IntegrationID != githubActions {
				t.Errorf("%q may be reported by anything but GitHub Actions", check.Context)
			}
		}
	}
	for _, rule := range []string{"deletion", "non_fast_forward", "pull_request", "required_status_checks"} {
		if !slices.Contains(types, rule) {
			t.Errorf("main is not held by the rule %s", rule)
		}
	}

	declared := workflows(t)
	var jobs []string
	for _, name := range []string{"ci.yml", "codeql.yml"} {
		for _, job := range jobName.FindAllStringSubmatch(declared[name], -1) {
			jobs = append(jobs, job[1])
		}
	}
	slices.Sort(jobs)
	slices.Sort(required)
	if !slices.Equal(jobs, required) {
		t.Errorf("the jobs are %q and main requires %q", jobs, required)
	}
}

func TestNothingIsReleasedFromATagNobodySigned(t *testing.T) {
	release := workflows(t)["release.yml"]
	if got := len(waitsOnTag.FindAllString(release, -1)); got != 2 {
		t.Errorf("%d jobs wait for the tag to be verified, want the two that package it", got)
	}
}
