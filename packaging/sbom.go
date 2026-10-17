package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

const (
	license    = "GPL-3.0-only"
	unasserted = "NOASSERTION"
	sbomSuffix = ".spdx.json"
)

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creation       `json:"creationInfo"`
	Packages          []component    `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

type creation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type component struct {
	SPDXID                string      `json:"SPDXID"`
	Name                  string      `json:"name"`
	VersionInfo           string      `json:"versionInfo"`
	PackageFileName       string      `json:"packageFileName,omitempty"`
	Supplier              string      `json:"supplier,omitempty"`
	DownloadLocation      string      `json:"downloadLocation"`
	FilesAnalyzed         bool        `json:"filesAnalyzed"`
	Checksums             []checksum  `json:"checksums,omitempty"`
	LicenseConcluded      string      `json:"licenseConcluded"`
	LicenseDeclared       string      `json:"licenseDeclared"`
	CopyrightText         string      `json:"copyrightText"`
	SourceInfo            string      `json:"sourceInfo,omitempty"`
	PrimaryPackagePurpose string      `json:"primaryPackagePurpose"`
	ExternalRefs          []reference `json:"externalRefs,omitempty"`
	Comment               string      `json:"comment,omitempty"`
}

type checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type reference struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func account(built *debug.BuildInfo, described release, binary, written string) (string, error) {
	agent, err := os.ReadFile(binary)
	if err != nil {
		return "", fmt.Errorf("read the agent: %w", err)
	}
	held, err := os.ReadFile(written)
	if err != nil {
		return "", fmt.Errorf("read the package: %w", err)
	}
	encoded, err := materials(built, described, filepath.Base(written), held, agent)
	if err != nil {
		return "", fmt.Errorf("list what %s holds: %w", filepath.Base(written), err)
	}
	target := strings.TrimSuffix(written, ".deb") + sbomSuffix
	if err := os.WriteFile(target, encoded, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", filepath.Base(target), err)
	}
	return target, nil
}

func materials(built *debug.BuildInfo, described release, name string, held, agent []byte) ([]byte, error) {
	toolchain := strings.Fields(built.GoVersion)
	if len(toolchain) == 0 {
		return nil, errors.New("it names no toolchain it was built with")
	}
	address, err := mail.ParseAddress(maintainer)
	if err != nil {
		return nil, fmt.Errorf("name the supplier %q: %w", maintainer, err)
	}
	supplier := fmt.Sprintf("Person: %s (%s)", address.Name, address.Address)
	settings := map[string]string{}
	var recorded []string
	for _, setting := range built.Settings {
		settings[setting.Key] = setting.Value
		recorded = append(recorded, setting.Key+"="+setting.Value)
	}
	packaged := sha256.Sum256(held)
	installed := sha256.Sum256(agent)
	components := []component{
		{
			SPDXID:                "SPDXRef-Package",
			Name:                  packageName,
			VersionInfo:           described.version,
			PackageFileName:       name,
			Supplier:              supplier,
			DownloadLocation:      unasserted,
			Checksums:             []checksum{{Algorithm: "SHA256", ChecksumValue: hex.EncodeToString(packaged[:])}},
			LicenseConcluded:      license,
			LicenseDeclared:       license,
			CopyrightText:         unasserted,
			PrimaryPackagePurpose: "INSTALL",
		},
		{
			SPDXID:                "SPDXRef-Agent",
			Name:                  built.Main.Path,
			VersionInfo:           built.Main.Version,
			PackageFileName:       agentPath,
			Supplier:              supplier,
			DownloadLocation:      "git+" + homepage + ".git@" + settings["vcs.revision"],
			Checksums:             []checksum{{Algorithm: "SHA256", ChecksumValue: hex.EncodeToString(installed[:])}},
			LicenseConcluded:      license,
			LicenseDeclared:       license,
			CopyrightText:         unasserted,
			SourceInfo:            fmt.Sprintf("built from commit %s, committed at %s", settings["vcs.revision"], settings["vcs.time"]),
			PrimaryPackagePurpose: "APPLICATION",
			ExternalRefs:          locate(built.Main.Path, built.Main.Version),
			Comment:               fmt.Sprintf("built by %s with %s", toolchain[0], strings.Join(recorded, " ")),
		},
		library("SPDXRef-GoStandardLibrary", "stdlib", toolchain[0], strings.TrimPrefix(toolchain[0], "go"), ""),
	}
	relationships := []relationship{
		{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package"},
		{SPDXElementID: "SPDXRef-Package", RelationshipType: "CONTAINS", RelatedSPDXElement: "SPDXRef-Agent"},
		{SPDXElementID: "SPDXRef-Agent", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "SPDXRef-GoStandardLibrary"},
	}
	identified := map[string]bool{}
	for _, component := range components {
		identified[component.SPDXID] = true
	}
	linked := slices.SortedFunc(slices.Values(built.Deps), func(a, b *debug.Module) int { return strings.Compare(a.Path, b.Path) })
	for _, module := range linked {
		used, said := module, ""
		if module.Replace != nil {
			used, said = module.Replace, fmt.Sprintf("replaces %s %s", module.Path, module.Version)
		}
		if used.Sum != "" {
			said = strings.TrimSpace(said + " go.sum " + used.Sum)
		}
		identifier := "SPDXRef-GoModule-" + strings.Map(func(character rune) rune {
			if character == '.' || character == '-' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
				return character
			}
			return '-'
		}, used.Path)
		if identified[identifier] {
			return nil, fmt.Errorf("two modules it links are both named %s", identifier)
		}
		identified[identifier] = true
		components = append(components, library(identifier, used.Path, used.Version, used.Version, said))
		relationships = append(relationships, relationship{SPDXElementID: "SPDXRef-Agent", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: identifier})
	}
	encoded, err := json.MarshalIndent(document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: fmt.Sprintf("%s/spdx/%s-%x", homepage, name, packaged),
		CreationInfo: creation{
			Created:  described.committed.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: " + modulePath + "/packaging@" + built.Main.Version},
		},
		Packages:      components,
		Relationships: relationships,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func library(identifier, name, version, located, said string) component {
	return component{
		SPDXID:                identifier,
		Name:                  name,
		VersionInfo:           version,
		DownloadLocation:      unasserted,
		LicenseConcluded:      unasserted,
		LicenseDeclared:       unasserted,
		CopyrightText:         unasserted,
		PrimaryPackagePurpose: "LIBRARY",
		ExternalRefs:          locate(name, located),
		Comment:               said,
	}
}

func locate(name, version string) []reference {
	var escaped strings.Builder
	for _, held := range []byte(version) {
		if held == '.' || held == '-' || held == '_' || held == '~' || held >= '0' && held <= '9' || held >= 'A' && held <= 'Z' || held >= 'a' && held <= 'z' {
			escaped.WriteByte(held)
		} else {
			fmt.Fprintf(&escaped, "%%%02X", held)
		}
	}
	return []reference{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/" + name + "@" + escaped.String()}}
}
