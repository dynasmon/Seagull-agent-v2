//go:build linux

package native_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// The platform asks the agent to run the release ahead while sshd keeps
// deciding, and the gate kills the installer twice: while dpkg configures the
// release, which leaves the agent's package halfway, and while the installer
// checks that it runs. The path unit starts the installer again on the
// installation it left pending, dpkg finishes what it left halfway, and the
// release ends installed on the same installation, with every outcome sshd
// decided meanwhile delivered.
func (c *chaos) interrupted(t *testing.T) {
	if *ahead == "" {
		t.Fatal("-ahead names no package of a later release, and the chaos interrupts an update to one")
	}
	aheadPackage, err := filepath.Abs(*ahead)
	if err != nil {
		t.Fatal(err)
	}
	aheadDebian := strings.TrimSpace(run(t, "dpkg-deb", "--field", aheadPackage, "Version"))
	releaser := newReleaser(t)
	envelope, err := proto.Marshal(releaser.root)
	if err != nil {
		t.Fatal(err)
	}
	place(t, updateRootPath, envelope)
	current, revision := stamped(t, agentPath)
	unpacked := filepath.Join(c.scratch, "ahead")
	run(t, "dpkg-deb", "--extract", aheadPackage, unpacked)
	later, laterRevision := stamped(t, filepath.Join(unpacked, "usr", "bin", "seagull-agent"))
	builtContent, aheadContent := contents(t, c.built), contents(t, aheadPackage)

	writing := c.write(t, "update", 6000, 50*time.Millisecond)
	c.platform.offering(releaser.offer(t, later, 1, releaser.release(current, revision, builtContent), releaser.release(later, laterRevision, aheadContent)), builtContent, aheadContent)
	c.updating = true
	c.gate.write(t)
	run(t, "systemctl", "restart", unit)
	c.invocation = started(t, c.invocation)

	deadline := time.Now().Add(4 * time.Minute)
	for answer("pgrep", "--full", packageName+`\.postinst configure`) == "" {
		if time.Now().After(deadline) {
			t.Fatalf("dpkg did not configure the release within 4m:\n%s", installerLog())
		}
		time.Sleep(20 * time.Millisecond)
	}
	run(t, "systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", installerUnit)
	if left := answer("dpkg-query", "--show", "--showformat=${Version} ${db:Status-Abbrev}", packageName); strings.HasSuffix(left, " ii") {
		t.Fatalf("killed as dpkg configured the release, the installer left the agent's package %q", left)
	}
	checking := c.stage(t, "checking", 4*time.Minute)
	run(t, "systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", installerUnit)
	installed := ended(t, "installed", checking["since"], 6*time.Minute)
	if installed["version"] != later || installed["previous"] != current || installed["failure"] != nil {
		t.Errorf("the installer ended at %v", installed)
	}
	if held := answer("dpkg-query", "--show", "--showformat=${Version} ${db:Status-Abbrev}", packageName); held != aheadDebian+" ii" {
		t.Errorf("dpkg holds the agent's package as %q, and it was updated to %s", held, aheadDebian)
	}
	resumed := strings.Count(answer("journalctl", "--no-pager", "--output", "cat", "--unit", installerUnit), `"msg":"update_install_resumed"`)
	if resumed < 2 {
		t.Errorf("the installer took the interrupted installation up again %d times:\n%s", resumed, installerLog())
	}
	if running, _ := stamped(t, agentPath); running != later {
		t.Errorf("the installed agent is %s, and it was updated to %s", running, later)
	}
	c.invocation = started(t, c.invocation)
	if again := await(t, c.invocation, "agent_starting", 20*time.Second); again["installation_id"] != c.installation {
		t.Errorf("the updated agent runs installation %v, and it ran %s", again["installation_id"], c.installation)
	}
	c.toldOfUpdate(t, agentv1.Status_Update_STAGE_INSTALLED, later, 2*time.Minute)
	writing.stop(t)
	c.settled(t, 3*time.Minute)
}

func (c *chaos) stage(t *testing.T, stage string, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		held := map[string]any{}
		content, err := os.ReadFile(filepath.Join(installerState, "journal.json"))
		if err == nil && json.Unmarshal(content, &held) == nil && held["stage"] == stage {
			return held
		}
		if time.Now().After(deadline) {
			t.Fatalf("the installer did not reach %s within %s: %v\n%s", stage, within, held, installerLog())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
