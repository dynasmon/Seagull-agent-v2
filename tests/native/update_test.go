//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/deb"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

var ahead = flag.String("ahead", "", "a Debian package of the same commit built as a later release, which the gate updates the installed agent to")

const (
	updateRootPath     = "/etc/seagull-agent/update-root.pb"
	watchUnit          = "seagull-agent-update.path"
	installerUnit      = "seagull-agent-update.service"
	installerState     = "/var/lib/seagull-agent-update"
	watchWants         = "/etc/systemd/system/paths.target.wants/seagull-agent-update.path"
	rootPayloadType    = "application/vnd.seagull.update.v1.root+protobuf"
	catalogPayloadType = "application/vnd.seagull.update.v1.catalog+protobuf"
)

var released = regexp.MustCompile(`^(v[0-9]+\.[0-9]+\.)([0-9]+)(-[0-9A-Za-z.-]+)?$`)

// The offer the platform hands an agent that asks whether to update, and the
// packages it holds, as the recorded platform answers: a 304 to an agent naming
// the offer it holds, and a package by its digest.
func (p *platform) offer(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	offered := p.offered
	p.mu.Unlock()
	if offered == nil {
		p.refuse(w, http.StatusNotFound, "agent_updates_not_configured", "this platform hands out no update")
		return
	}
	sum := sha256.Sum256(offered)
	tag := strconv.Quote(hex.EncodeToString(sum[:]))
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(offered)
}

func (p *platform) hand(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	content, held := p.packages[strings.TrimPrefix(r.URL.Path, "/v1/agents/update/packages/")]
	p.mu.Unlock()
	if !held {
		p.refuse(w, http.StatusNotFound, "unknown_package", "no package is held under that digest for this agent")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

func (p *platform) refuse(w http.ResponseWriter, status int, code, detail string) {
	encoded, _ := proto.Marshal(&controlv1.Refusal{Code: code, Detail: detail})
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(status)
	w.Write(encoded)
}

func (p *platform) offering(offer []byte, packages ...[]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.offered, p.packages = offer, map[string][]byte{}
	for _, content := range packages {
		sum := sha256.Sum256(content)
		p.packages[hex.EncodeToString(sum[:])] = content
	}
}

// An operator's offline key, which signs the root the agent is provisioned with
// and every catalog of releases after it.
type releaser struct {
	key  *ecdsa.PrivateKey
	id   string
	root *updatev1.Envelope
}

func newReleaser(t *testing.T) *releaser {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key that signs releases: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the key that signs releases: %v", err)
	}
	sum := sha256.Sum256(der)
	held := &releaser{key: key, id: hex.EncodeToString(sum[:])}
	now := time.Now().UTC()
	held.root = held.seal(t, &updatev1.Root{
		SchemaVersion: 1,
		Version:       1,
		IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(now.Add(30 * 24 * time.Hour)),
		Keys:          []*updatev1.Key{{Keyid: held.id, PublicKey: der}},
		Root:          &updatev1.Role{Keyids: []string{held.id}, Threshold: 1},
		Catalog:       &updatev1.Role{Keyids: []string{held.id}, Threshold: 1},
	}, rootPayloadType)
	return held
}

func (r *releaser) seal(t *testing.T, message proto.Message, payloadType string) *updatev1.Envelope {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatalf("encode the metadata: %v", err)
	}
	authenticated := fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	digest := sha256.Sum256(append(authenticated, payload...))
	signature, err := ecdsa.SignASN1(rand.Reader, r.key, digest[:])
	if err != nil {
		t.Fatalf("sign the metadata: %v", err)
	}
	return &updatev1.Envelope{Payload: payload, PayloadType: payloadType, Signatures: []*updatev1.Signature{{Sig: signature, Keyid: r.id}}}
}

func (r *releaser) release(version, revision string, content []byte) *updatev1.Release {
	sum := sha256.Sum256(content)
	return &updatev1.Release{
		Version:       version,
		Platform:      &updatev1.Platform{Os: "linux", Architecture: runtime.GOARCH, Format: updatev1.Format_FORMAT_DEB},
		Payload:       &updatev1.Payload{Sha256: sum[:], Size: uint64(len(content))},
		Source:        &updatev1.Source{Repository: "github.com/dynasmon/Seagull-agent-v2", Revision: revision},
		Compatibility: &updatev1.Compatibility{StateGeneration: 1},
	}
}

func (r *releaser) offer(t *testing.T, version string, catalog uint64, releases ...*updatev1.Release) []byte {
	t.Helper()
	now := time.Now().UTC()
	encoded, err := proto.Marshal(&updatev1.Offer{
		Roots: []*updatev1.Envelope{r.root},
		Catalog: r.seal(t, &updatev1.Catalog{
			SchemaVersion: 1,
			Version:       catalog,
			IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
			ExpiresAt:     timestamppb.New(now.Add(7 * 24 * time.Hour)),
			Releases:      releases,
		}, catalogPayloadType),
		Version: version,
	})
	if err != nil {
		t.Fatalf("encode the offer: %v", err)
	}
	return encoded
}

func stamped(t *testing.T, binary string) (string, string) {
	t.Helper()
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatalf("read how %s was built: %v", binary, err)
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return info.Main.Version, setting.Value
		}
	}
	t.Fatalf("%s was built as %s from no revision Go recorded", binary, info.Main.Version)
	return "", ""
}

func contents(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return content
}

// A release that installs and never runs: the release ahead under the next
// version, its binary replaced by one that exits at once.
func (g *gate) unrunnable(t *testing.T, from, version string) (string, []byte) {
	t.Helper()
	parts := released.FindStringSubmatch(version)
	if parts == nil {
		t.Fatalf("the release ahead is %s, which the gate cannot name a later release after", version)
	}
	patch, _ := strconv.Atoi(parts[2])
	broken := parts[1] + strconv.Itoa(patch+1) + parts[3]
	packaged, err := deb.Version(broken)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(g.scratch, "unrunnable")
	run(t, "dpkg-deb", "--raw-extract", from, root)
	binary := []byte("#!/bin/sh\necho 'this release does not run' >&2\nexit 1\n")
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "seagull-agent"), binary, 0o755); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(root, "DEBIAN", "control")
	held := strings.TrimSpace(run(t, "dpkg-deb", "--field", from, "Version"))
	declared := string(contents(t, control))
	renamed := strings.Replace(declared, "\nVersion: "+held+"\n", "\nVersion: "+packaged+"\n", 1)
	if renamed == declared {
		t.Fatalf("the control file declares no version %s:\n%s", held, declared)
	}
	sums := filepath.Join(root, "DEBIAN", "md5sums")
	var listed []string
	for _, line := range strings.Split(strings.TrimSpace(string(contents(t, sums))), "\n") {
		if strings.HasSuffix(line, "  usr/bin/seagull-agent") {
			line = fmt.Sprintf("%x  usr/bin/seagull-agent", md5.Sum(binary))
		}
		listed = append(listed, line)
	}
	if err := os.WriteFile(control, []byte(renamed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sums, []byte(strings.Join(listed, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	built := filepath.Join(g.scratch, "seagull-agent_unrunnable.deb")
	run(t, "dpkg-deb", "--root-owner-group", "--build", root, built)
	return broken, contents(t, built)
}

func installerLog() string {
	return answer("journalctl", "--no-pager", "--output", "cat", "--unit", installerUnit, "--lines", "60")
}

func ended(t *testing.T, stage string, before any, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		held := map[string]any{}
		content, err := os.ReadFile(filepath.Join(installerState, "journal.json"))
		if err == nil && json.Unmarshal(content, &held) == nil && held["since"] != before {
			switch held["stage"] {
			case stage:
				return held
			case "installed", "rolled_back", "failed":
				t.Fatalf("the installer ended at %v, not at %s:\n%s", held, stage, installerLog())
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the installer did not end at %s within %s: %v\n%s", stage, within, held, installerLog())
		}
		time.Sleep(time.Second)
	}
}

func (g *gate) toldOfUpdate(t *testing.T, stage agentv1.Status_Update_Stage, version string, within time.Duration) *agentv1.Status_Update {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		reports := g.platform.told()
		for index := len(reports) - 1; index >= 0; index-- {
			if told := reports[index].GetUpdate(); told.GetStage() == stage && told.GetVersion() == version {
				return told
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the platform was not told within %s that the update to %s reached %s", within, version, stage)
		}
		time.Sleep(time.Second)
	}
}

// An operator signs a catalog off the platform and the platform asks the agent
// to run the release ahead: the agent stages it, the installer verifies it again
// and installs it as root, and the agent it runs is the same installation once
// it ran as it should. A release that installs and never runs is undone, and the
// installation runs the release before it again.
func (g *gate) updates(t *testing.T) {
	if *ahead == "" {
		t.Skip("-ahead names no package of a later release, so the gate has nothing to update the agent to")
	}
	heard := len(g.platform.told())
	aheadPackage, err := filepath.Abs(*ahead)
	if err != nil {
		t.Fatal(err)
	}
	aheadDebian := strings.TrimSpace(run(t, "dpkg-deb", "--field", aheadPackage, "Version"))
	if exec.Command("dpkg", "--compare-versions", aheadDebian, "gt", g.nextVersion).Run() != nil {
		t.Fatalf("-ahead names %s, which is no later release than %s, the one installed", aheadDebian, g.nextVersion)
	}
	releaser := newReleaser(t)
	envelope, err := proto.Marshal(releaser.root)
	if err != nil {
		t.Fatal(err)
	}
	place(t, updateRootPath, envelope)
	current, revision := stamped(t, agentPath)
	unpacked := filepath.Join(g.scratch, "ahead")
	run(t, "dpkg-deb", "--extract", aheadPackage, unpacked)
	later, laterRevision := stamped(t, filepath.Join(unpacked, "usr", "bin", "seagull-agent"))
	builtContent, aheadContent := contents(t, g.built), contents(t, aheadPackage)

	g.platform.offering(releaser.offer(t, later, 1, releaser.release(current, revision, builtContent), releaser.release(later, laterRevision, aheadContent)), builtContent, aheadContent)
	g.updating = true
	g.write(t)
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	installed := ended(t, "installed", nil, 4*time.Minute)
	if installed["version"] != later || installed["previous"] != current || installed["failure"] != nil {
		t.Errorf("the installer ended at %v", installed)
	}
	if held := run(t, "dpkg-query", "--show", "--showformat=${Version}", packageName); held != aheadDebian {
		t.Errorf("dpkg holds %s after the update, and the release ahead is %s", held, aheadDebian)
	}
	if running, _ := stamped(t, agentPath); running != later {
		t.Errorf("the installed agent is %s, and it was updated to %s", running, later)
	}
	g.invocation = started(t, g.invocation)
	if again := await(t, g.invocation, "agent_starting", 20*time.Second); again["installation_id"] != g.installation {
		t.Errorf("the updated agent runs installation %v, and it ran %s", again["installation_id"], g.installation)
	}
	if told := g.toldOfUpdate(t, agentv1.Status_Update_STAGE_INSTALLED, later, 2*time.Minute); told.GetCatalogVersion() != 1 || told.GetRootVersion() != 1 {
		t.Errorf("the platform was told %v", told)
	}
	if active, result := answer("systemctl", "is-active", installerUnit), answer("systemctl", "show", "--property", "Result", "--value", installerUnit); active != "inactive" || result != "success" {
		t.Errorf("the installer is %s with result %s once it ended", active, result)
	}
	for _, gone := range []string{filepath.Join(state, "staged", "ready"), filepath.Join(installerState, "pending")} {
		if _, err := os.Lstat(gone); err == nil {
			t.Errorf("an installation that ended left %s", gone)
		}
	}
	g.statusSays(t, true, "\nupdate: running since ", later+": installed")

	broken, unrunnable := g.unrunnable(t, aheadPackage, later)
	g.platform.offering(releaser.offer(t, broken, 2, releaser.release(later, laterRevision, aheadContent), releaser.release(broken, laterRevision, unrunnable)), aheadContent, unrunnable)
	rolledBack := ended(t, "rolled_back", installed["since"], 8*time.Minute)
	if rolledBack["version"] != broken || rolledBack["previous"] != later || rolledBack["failure"] != "unhealthy" {
		t.Errorf("the installer ended at %v", rolledBack)
	}
	if held := run(t, "dpkg-query", "--show", "--showformat=${Version}", packageName); held != aheadDebian {
		t.Errorf("dpkg holds %s after going back, and the release before is %s", held, aheadDebian)
	}
	g.invocation = started(t, g.invocation)
	if again := await(t, g.invocation, "agent_starting", 20*time.Second); again["installation_id"] != g.installation {
		t.Errorf("after going back the agent runs installation %v, and it ran %s", again["installation_id"], g.installation)
	}
	if told := g.toldOfUpdate(t, agentv1.Status_Update_STAGE_ROLLED_BACK, broken, 2*time.Minute); told.GetFailure() != agentv1.Status_Update_FAILURE_UNHEALTHY || told.GetCatalogVersion() != 2 {
		t.Errorf("the platform was told %v", told)
	}
	g.statusSays(t, false, "\nupdate: degraded since ", broken+": rolled_back, unhealthy")

	run(t, "systemctl", "stop", unit)
	g.platform.offering(nil)
	g.updating = false
	g.write(t)
	if *evidence != "" {
		g.recordUpdates(t, heard)
	}
}

func (g *gate) recordUpdates(t *testing.T, from int) {
	t.Helper()
	directory := filepath.Join(*evidence, "update-status")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	type told struct {
		Batch    string `json:"batch"`
		Sequence uint64 `json:"sequence"`
		Stage    string `json:"stage"`
		Version  string `json:"version"`
		Failure  string `json:"failure"`
	}
	scenario := struct {
		RecordedAt     time.Time `json:"recorded_at"`
		InstallationID string    `json:"installation_id"`
		AgentID        string    `json:"agent_id"`
		Reports        []told    `json:"reports"`
	}{RecordedAt: time.Now().UTC(), InstallationID: g.installation, AgentID: agentID}
	batches, reports := g.platform.statusBatches(), g.platform.told()
	for index := from; index < len(batches); index++ {
		update := reports[index].GetUpdate()
		if update == nil {
			continue
		}
		name := fmt.Sprintf("batch-%03d.pb", len(scenario.Reports))
		if err := os.WriteFile(filepath.Join(directory, name), batches[index], 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		scenario.Reports = append(scenario.Reports, told{Batch: name, Sequence: reports[index].GetSequence(),
			Stage: update.GetStage().String(), Version: update.GetVersion(), Failure: update.GetFailure().String()})
	}
	encoded, err := json.MarshalIndent(scenario, "", "  ")
	if err != nil {
		t.Fatalf("encode the scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "scenario.json"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write the scenario: %v", err)
	}
}
