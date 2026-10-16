package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

func TestTheBillOfMaterialsNamesThePackageTheAgentAndEveryModuleItLinks(t *testing.T) {
	info := linked()
	described, err := describe(info)
	if err != nil {
		t.Fatalf("describe the build: %v", err)
	}
	name := "seagull-agent_" + described.version + "_amd64.deb"
	held, agent := []byte("the package"), []byte("the agent")
	encoded, err := materials(info, described, name, held, agent)
	if err != nil {
		t.Fatalf("list what the package holds: %v", err)
	}
	var read map[string]any
	if err := json.Unmarshal(encoded, &read); err != nil {
		t.Fatalf("read the bill of materials: %v", err)
	}
	for field, want := range map[string]string{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              name,
		"documentNamespace": homepage + "/spdx/" + name + "-" + summed(held),
	} {
		if read[field] != want {
			t.Errorf("the document says %s is %v, want %q", field, read[field], want)
		}
	}
	creation, _ := read["creationInfo"].(map[string]any)
	if creators, _ := creation["creators"].([]any); creation["created"] != "2026-09-26T00:43:46Z" || len(creators) != 1 || !strings.HasPrefix(creators[0].(string), "Tool: ") {
		t.Errorf("the document was created as %v", creation)
	}

	named := regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)
	components := map[string]map[string]any{}
	for _, listed := range read["packages"].([]any) {
		component := listed.(map[string]any)
		identifier, _ := component["SPDXID"].(string)
		if !named.MatchString(identifier) || components[identifier] != nil {
			t.Errorf("a package is identified as %q", identifier)
		}
		if analyzed, present := component["filesAnalyzed"]; !present || analyzed != false {
			t.Errorf("%s says its files were analyzed: %v", identifier, analyzed)
		}
		components[identifier] = component
	}
	contracts, protobuf, fork := "SPDXRef-GoModule-github.com-dynasmon-Seagull-contracts", "SPDXRef-GoModule-google.golang.org-protobuf", "SPDXRef-GoModule-example.com-fork"
	if want := []string{"SPDXRef-Agent", fork, contracts, protobuf, "SPDXRef-GoStandardLibrary", "SPDXRef-Package"}; !slices.Equal(slices.Sorted(maps.Keys(components)), want) {
		t.Fatalf("the document lists the packages %v, want %v", components, want)
	}
	for _, c := range []struct {
		identifier, field, want string
	}{
		{"SPDXRef-Package", "name", packageName},
		{"SPDXRef-Package", "versionInfo", described.version},
		{"SPDXRef-Package", "packageFileName", name},
		{"SPDXRef-Package", "supplier", "Person: Nathan (nathanmblima@gmail.com)"},
		{"SPDXRef-Package", "licenseDeclared", "GPL-3.0-only"},
		{"SPDXRef-Package", "primaryPackagePurpose", "INSTALL"},
		{"SPDXRef-Package", "sha256", summed(held)},
		{"SPDXRef-Agent", "name", modulePath},
		{"SPDXRef-Agent", "versionInfo", "v0.0.0-20260926004346-7d7db5969ad5"},
		{"SPDXRef-Agent", "packageFileName", "usr/bin/seagull-agent"},
		{"SPDXRef-Agent", "downloadLocation", "git+https://github.com/dynasmon/Seagull-agent-v2.git@7d7db5969ad555287048c591dd2e991198184f46"},
		{"SPDXRef-Agent", "primaryPackagePurpose", "APPLICATION"},
		{"SPDXRef-Agent", "sha256", summed(agent)},
		{"SPDXRef-Agent", "purl", "pkg:golang/github.com/dynasmon/Seagull-agent-v2@v0.0.0-20260926004346-7d7db5969ad5"},
		{"SPDXRef-GoStandardLibrary", "versionInfo", "go1.26.9"},
		{"SPDXRef-GoStandardLibrary", "purl", "pkg:golang/stdlib@1.26.9"},
		{contracts, "versionInfo", "v0.19.0"},
		{contracts, "purl", "pkg:golang/github.com/dynasmon/Seagull-contracts@v0.19.0"},
		{contracts, "comment", "go.sum h1:S8+R0z0y4Mnqc8rqIE2PEtaXwo9Las2Ld629SynmoIM="},
		{protobuf, "purl", "pkg:golang/google.golang.org/protobuf@v1.36.11"},
		{fork, "name", "example.com/fork"},
		{fork, "purl", "pkg:golang/example.com/fork@v1.0.1%2Bincompatible"},
		{fork, "comment", "replaces example.com/forked v1.0.0 go.sum h1:Zm9yaw=="},
		{fork, "licenseDeclared", "NOASSERTION"},
		{fork, "primaryPackagePurpose", "LIBRARY"},
	} {
		if got := field(components[c.identifier], c.field); got != c.want {
			t.Errorf("%s says %s is %q, want %q", c.identifier, c.field, got, c.want)
		}
	}
	for _, want := range []string{"built by go1.26.9 with", "-trimpath=true", "CGO_ENABLED=0", "GOAMD64=v1", "vcs.revision=7d7db5969ad555287048c591dd2e991198184f46", "vcs.modified=false"} {
		if said := field(components["SPDXRef-Agent"], "comment"); !strings.Contains(said, want) {
			t.Errorf("the agent's build is described as %q, which does not say %q", said, want)
		}
	}

	var related []string
	for _, listed := range read["relationships"].([]any) {
		relation := listed.(map[string]any)
		related = append(related, relation["spdxElementId"].(string)+" "+relation["relationshipType"].(string)+" "+relation["relatedSpdxElement"].(string))
	}
	want := []string{
		"SPDXRef-Agent DEPENDS_ON " + contracts,
		"SPDXRef-Agent DEPENDS_ON " + fork,
		"SPDXRef-Agent DEPENDS_ON " + protobuf,
		"SPDXRef-Agent DEPENDS_ON SPDXRef-GoStandardLibrary",
		"SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package",
		"SPDXRef-Package CONTAINS SPDXRef-Agent",
	}
	if slices.Sort(related); !slices.Equal(related, slices.Sorted(slices.Values(want))) {
		t.Errorf("the document relates %q, want %q", related, want)
	}
}

func TestTheSameBuildIsListedInTheSameBytesAndTheListNamesItsOwnPackage(t *testing.T) {
	info := linked()
	described, err := describe(info)
	if err != nil {
		t.Fatalf("describe the build: %v", err)
	}
	listedFor := func(held []byte) []byte {
		t.Helper()
		encoded, err := materials(info, described, "seagull-agent_0.1.0-1_amd64.deb", held, []byte("the agent"))
		if err != nil {
			t.Fatalf("list what the package holds: %v", err)
		}
		return encoded
	}
	first, again, other := listedFor([]byte("the package")), listedFor([]byte("the package")), listedFor([]byte("another package"))
	if !bytes.Equal(first, again) {
		t.Error("the same build is listed in two different documents")
	}
	if bytes.Equal(first, other) || !bytes.Contains(other, []byte(summed([]byte("another package")))) || bytes.Contains(other, []byte(summed([]byte("the package")))) {
		t.Error("the document of one package names another one")
	}
}

func TestTwoModulesNamedAlikeAreNotListedAsOne(t *testing.T) {
	info := linked()
	info.Deps = []*debug.Module{{Path: "example.com/a_b", Version: "v1.0.0"}, {Path: "example.com/a-b", Version: "v1.0.0"}}
	described, err := describe(info)
	if err != nil {
		t.Fatalf("describe the build: %v", err)
	}
	if _, err := materials(info, described, "seagull-agent_0.1.0-1_amd64.deb", nil, nil); err == nil || !strings.Contains(err.Error(), "SPDXRef-GoModule-example.com-a-b") {
		t.Errorf("two modules named alike are listed: %v", err)
	}
}

func TestTheBillOfMaterialsIsWrittenBesideThePackage(t *testing.T) {
	info := linked()
	described, err := describe(info)
	if err != nil {
		t.Fatalf("describe the build: %v", err)
	}
	directory := t.TempDir()
	binary, written := filepath.Join(directory, "seagull-agent"), filepath.Join(directory, "seagull-agent_0.1.0-1_amd64.deb")
	for name, content := range map[string]string{binary: "the agent", written: "the package"} {
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := account(info, described, binary, written)
	if err != nil || listed != filepath.Join(directory, "seagull-agent_0.1.0-1_amd64.spdx.json") {
		t.Fatalf("the bill of materials is written as %s (%v)", listed, err)
	}
	read, err := os.ReadFile(listed)
	want, _ := materials(info, described, filepath.Base(written), []byte("the package"), []byte("the agent"))
	if err != nil || !bytes.Equal(read, want) {
		t.Errorf("the bill of materials beside the package is not the one of the package: %v", err)
	}
}

func linked() *debug.BuildInfo {
	info := built(nil)
	info.GoVersion = "go1.26.9"
	info.Deps = []*debug.Module{
		{Path: "google.golang.org/protobuf", Version: "v1.36.11", Sum: "h1:fV6ZwhNocDyBLK0dj+fg8ektcVegBBuEolpbTQyBNVE="},
		{Path: "github.com/dynasmon/Seagull-contracts", Version: "v0.19.0", Sum: "h1:S8+R0z0y4Mnqc8rqIE2PEtaXwo9Las2Ld629SynmoIM="},
		{Path: "example.com/forked", Version: "v1.0.0", Sum: "h1:Zm9ya2Vk", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1+incompatible", Sum: "h1:Zm9yaw=="}},
	}
	return info
}

func summed(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func field(component map[string]any, name string) string {
	switch name {
	case "sha256":
		checksums, _ := component["checksums"].([]any)
		for _, listed := range checksums {
			if held := listed.(map[string]any); held["algorithm"] == "SHA256" {
				return held["checksumValue"].(string)
			}
		}
		return ""
	case "purl":
		references, _ := component["externalRefs"].([]any)
		for _, listed := range references {
			if held := listed.(map[string]any); held["referenceCategory"] == "PACKAGE-MANAGER" && held["referenceType"] == "purl" {
				return held["referenceLocator"].(string)
			}
		}
		return ""
	}
	said, _ := component[name].(string)
	return said
}
