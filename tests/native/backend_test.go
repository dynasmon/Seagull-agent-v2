//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var backend = flag.String("backend", "", "a directory a platform running beside the test left its ingest listener and the authority of its agents in, where the test leaves what sshd decided")

const stopTheBroker = "SEAGULL-CHAOS stop the broker"

// The installed agent against the platform's own ingest gateway, backbone and
// store, which a recorder runs beside the test and reads once it ends: sshd
// keeps deciding while the gate kills the agent and the recorder stops the
// backbone for a while, and the agent delivers every outcome. What the
// platform kept of them is the recorder's to count, by the event identifiers.
func TestTheInstalledAgentDeliversToAPlatformWhoseBackboneStopsForAWhile(t *testing.T) {
	if *backend == "" {
		t.Skip("-backend names no directory a platform running beside the test left its listener in")
	}
	var running struct {
		IngestURL string `json:"ingest_url"`
		Authority string `json:"authority"`
		Key       string `json:"key"`
	}
	content, err := os.ReadFile(filepath.Join(*backend, "platform.json"))
	if err == nil {
		err = json.Unmarshal(content, &running)
	}
	if err != nil {
		t.Fatalf("read what the platform left in %s: %v", *backend, err)
	}
	authorityPEM, err := os.ReadFile(filepath.Join(*backend, running.Authority))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &authority{}
	if block, _ := pem.Decode(authorityPEM); block != nil {
		issuer.certificate, err = x509.ParseCertificate(block.Bytes)
	}
	keyPEM, read := os.ReadFile(filepath.Join(*backend, running.Key))
	if block, _ := pem.Decode(keyPEM); read == nil && block != nil && err == nil {
		var parsed any
		if parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			parsed, err = x509.ParseECPrivateKey(block.Bytes)
		}
		issuer.key, _ = parsed.(*ecdsa.PrivateKey)
	}
	if err = errors.Join(err, read); err != nil || issuer.certificate == nil || issuer.key == nil {
		t.Fatalf("read the authority of the platform's agents: %v", err)
	}

	c := openChaos(t)
	c.install(t)
	c.collects = true
	c.tuned = map[string]any{"server": map[string]any{"ingest_url": running.IngestURL, "renewal_url": c.platform.address(c.platform.renewal), "trust_bundle": bundle}}
	c.gate.write(t)
	place(t, bundle, append(c.platform.bundle(), authorityPEM...))
	if said, err := as(t, "-config", configuration, "config", "check"); err != nil {
		t.Fatalf("the service account cannot read the settings: %v\n%s", err, said)
	}
	c.reissue(t, issuer, []*authority{issuer}, 2*time.Hour)
	c.start(t)
	await(t, c.invocation, "collection_started", 10*time.Second)
	began := time.Now()

	writing := c.write(t, "loop", 2400, 40*time.Millisecond)
	asked, killed := false, 0
	for !writing.done() {
		time.Sleep(time.Duration(4000+c.draw(4000)) * time.Millisecond)
		if !asked && time.Since(began) > 20*time.Second {
			fmt.Println(stopTheBroker)
			asked = true
			restarted := filepath.Join(*backend, "backbone-restarted")
			for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(time.Second) {
				if _, err := os.Stat(restarted); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the recorder did not start the backbone again within 3m")
				}
			}
			continue
		}
		if writing.done() {
			break
		}
		c.kill(t)
		killed++
	}
	writing.wait(t)
	if !asked {
		t.Fatal("sshd's stand-in was done before the recorder was asked to stop the backbone")
	}
	c.says(t, "events: nothing waiting", 5*time.Minute)
	held := answer("journalctl", "--no-pager", "--output", "cat", "--unit", unit, "--since", fmt.Sprintf("@%d", began.Unix()))
	if !strings.Contains(held, `"msg":"delivery_failed"`) || !strings.Contains(held, `"outcome":"unconfirmed"`) {
		t.Errorf("the agent never failed to deliver while the recorder stopped the backbone:\n%s", held)
	}
	run(t, "systemctl", "restart", unit)
	c.invocation = started(t, c.invocation)
	opened := await(t, c.invocation, "spool_opened", 10*time.Second)

	c.mu.Lock()
	produced := append([]string(nil), c.produced...)
	c.mu.Unlock()
	left, err := json.MarshalIndent(map[string]any{
		"build":           strings.SplitN(run(t, agentPath, "-version"), "\n", 2)[0],
		"installation_id": c.installation,
		"agent_id":        agentID,
		"kills":           killed,
		"produced":        produced,
		"spool":           opened["events"],
	}, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(*backend, "agent.json"), append(left, '\n'), 0o644)
	}
	if err != nil {
		t.Fatal(err)
	}
	if events, _ := opened["events"].(map[string]any); events["outstanding"] != float64(0) || events["lost"] != float64(0) ||
		events["quarantined"] != float64(0) || events["expired"] != float64(0) {
		t.Errorf("after delivering to the platform the agent opened its spool as %v", events)
	}
	run(t, "systemctl", "stop", unit)
}
