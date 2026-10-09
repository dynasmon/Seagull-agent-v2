//go:build linux

package native_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	socketsVariable = "SEAGULL_NATIVE_SOCKETS"
	networkDropIn   = "network.conf"
	listenerUnit    = "seagull-native-gate-listener.service"
	connectorUnit   = "seagull-native-gate-connector.service"
	isolatedUnit    = "seagull-native-gate-isolated.service"
	joinedUnit      = "seagull-native-gate-joined.service"
	heldUnit        = "seagull-native-gate-held.service"
	nestedUnit      = "seagull-native-gate-nested.service"
	shownOnly       = "[Service]\nProtectProc=default\n"
	associating     = "[Service]\nProtectProc=default\nReadOnlyPaths=/proc\nCapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\nAmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\nSystemCallFilter=~process_vm_readv process_vm_writev\n"
)

// holding opens the sockets it is given, such as "listen tcp4 127.0.0.1:47001"
// or "connect tcp6 [::1]:47001", separated by commas, takes what reaches its
// listeners and holds everything until it is stopped. Every connection it
// holds is reset as it closes, so neither side waits in TIME_WAIT.
func holding(given string) int {
	for _, socket := range strings.Split(given, ",") {
		fields := strings.Fields(socket)
		if len(fields) != 3 {
			fmt.Fprintf(os.Stderr, "%q names no socket\n", socket)
			return 2
		}
		var err error
		switch {
		case fields[0] == "listen" && strings.HasPrefix(fields[1], "udp"):
			_, err = net.ListenPacket(fields[1], fields[2])
		case fields[0] == "listen":
			var listening net.Listener
			if listening, err = net.Listen(fields[1], fields[2]); err == nil {
				go accepting(listening)
			}
		case fields[0] == "connect":
			var connected net.Conn
			if connected, err = net.Dial(fields[1], fields[2]); err == nil {
				err = connected.(*net.TCPConn).SetLinger(0)
			}
		default:
			err = fmt.Errorf("%q is no way to hold a socket", fields[0])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	fmt.Println("holding")
	for {
		time.Sleep(time.Hour)
	}
}

func accepting(listening net.Listener) {
	for {
		connected, err := listening.Accept()
		if err != nil {
			return
		}
		connected.(*net.TCPConn).SetLinger(0)
		go io.Copy(io.Discard, connected)
	}
}

func (g *gate) sockets(t *testing.T) {
	installed := filepath.Join(probeHome, "native.test")
	if err := os.MkdirAll(probeHome, 0o755); err != nil {
		t.Fatalf("create %s: %v", probeHome, err)
	}
	copySelf(t, installed)
	t.Cleanup(func() {
		for _, held := range []string{listenerUnit, connectorUnit, isolatedUnit, joinedUnit, heldUnit, nestedUnit} {
			exec.Command("systemctl", "stop", held).Run()
		}
		os.RemoveAll(probeHome)
		os.Remove(filepath.Join(overrides, networkDropIn))
		os.Remove(filepath.Join(overrides, "probe.conf"))
		exec.Command("systemctl", "daemon-reload").Run()
	})

	g.listening, g.debugging = true, true
	g.collecting(t, g.collects)
	watched := g.networked(t, "network_watched")
	t.Logf("the agent took the baseline of %v listeners and %v flows in %v namespaces in %v ns", watched["listeners"], watched["flows"], watched["namespaces"], watched["took"])
	hidden := g.networked(t, "network_not_covered")
	if reason, recovery := fmt.Sprint(hidden["reason"]), fmt.Sprint(hidden["recovery"]); hidden["level"] != "WARN" || !strings.Contains(reason, "procfs hides the processes of other accounts") ||
		!strings.Contains(recovery, "ProtectProc=default") || !strings.Contains(recovery, "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH") {
		t.Errorf("with the service hiding the processes of other accounts, the agent said %v", hidden)
	}
	g.statusSays(t, true, "\nmodule network: running", "not seeing the network namespaces other than the agent's own")

	hold(t, listenerUnit, installed, "listen tcp4 127.0.0.1:47001,listen tcp6 [::1]:47001,listen udp4 127.0.0.1:47002")
	for _, at := range []struct {
		protocol, address string
		port              float64
	}{{"tcp", "127.0.0.1", 47001}, {"tcp", "::1", 47001}, {"udp", "127.0.0.1", 47002}} {
		opened := g.listener(t, "listener_opened", at.address, at.port)
		if namespace, _ := opened["namespace"].(map[string]any); opened["protocol"] != at.protocol || fmt.Sprint(opened["accounts"]) != "[nobody]" || opened["association"] != "accounts" ||
			fmt.Sprint(opened["processes"]) != "[]" || opened["origin"] != "interval" || namespace["own"] != true || !strings.HasPrefix(fmt.Sprint(namespace["id"]), "net:[") {
			t.Errorf("a listener of nobody at %s port %v was said as %v", at.address, at.port, opened)
		}
	}

	hold(t, connectorUnit, installed, "connect tcp4 127.0.0.1:47001,connect tcp6 [::1]:47001")
	for _, way := range []struct{ direction, remote string }{{"outbound", "127.0.0.1"}, {"inbound", "127.0.0.1"}, {"outbound", "::1"}, {"inbound", "::1"}} {
		started := g.flow(t, "flow_started", way.direction, way.remote, 47001)
		if started["protocol"] != "tcp" || started["account"] != "nobody" || started["association"] != "accounts" || started["connections"] != float64(1) || fmt.Sprint(started["states"]) != "[established]" {
			t.Errorf("an %s connection of nobody with %s was said as %v", way.direction, way.remote, started)
		}
	}
	run(t, "systemctl", "stop", connectorUnit, listenerUnit)
	if closed := g.listener(t, "listener_closed", "127.0.0.1", 47001); fmt.Sprint(closed["accounts"]) != "[nobody]" {
		t.Errorf("the listener of nobody that closed was said as %v", closed)
	}
	if ended := g.flow(t, "flow_ended", "outbound", "127.0.0.1", 47001); ended["account"] != "nobody" || ended["connections"] != float64(1) || ended["first"] == nil || ended["last"] == nil {
		t.Errorf("the connection of nobody that ended was said as %v", ended)
	}

	hold(t, isolatedUnit, installed, "listen tcp4 127.0.0.1:47003", "--property=PrivateNetwork=yes")
	g.rounds(t, 2)
	if g.saidOf(t, "listener_opened", "127.0.0.1", 47003) != nil {
		t.Errorf("with the service hiding the processes of other accounts, the agent saw a listener in another network namespace")
	}

	place(t, filepath.Join(overrides, networkDropIn), []byte(shownOnly))
	run(t, "systemctl", "daemon-reload")
	g.restarted(t)
	if observed := g.networked(t, "network_observed"); observed["because"] != "start" {
		t.Errorf("started again, the agent observed %v", observed)
	}
	isolated := propertyOf(t, isolatedUnit, "MainPID")
	hold(t, joinedUnit, installed, "listen tcp4 127.0.0.1:47004", "--property=NetworkNamespacePath=/proc/"+isolated+"/ns/net")
	joined := g.listener(t, "listener_opened", "127.0.0.1", 47004)
	if namespace, _ := joined["namespace"].(map[string]any); namespace["own"] != false || fmt.Sprint(namespace["process"]) != isolated || namespace["name"] != "native.test" ||
		namespace["id"] != nil || fmt.Sprint(joined["accounts"]) != "[nobody]" || joined["association"] != "accounts" {
		t.Errorf("a listener in the namespace of process %s was said as %v", isolated, joined)
	}
	if g.saidOf(t, "listener_opened", "127.0.0.1", 47003) != nil {
		t.Errorf("a listener the agent first saw as it started was said as opened")
	}
	if unread := g.networked(t, "network_not_covered"); !strings.Contains(fmt.Sprint(unread["reason"]), "the agent may not read the descriptors of") ||
		!strings.Contains(fmt.Sprint(unread["recovery"]), "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH") || strings.Contains(fmt.Sprint(unread["reason"]), "procfs hides") {
		t.Errorf("with the service showing every process, the agent said %v", unread)
	}

	place(t, filepath.Join(overrides, networkDropIn), []byte(associating))
	place(t, filepath.Join(overrides, "probe.conf"), fmt.Appendf(nil, "[Service]\nExecStartPre=/usr/bin/env %s=network-%d %s\n", probeVariable, time.Now().UnixNano(), installed))
	run(t, "systemctl", "daemon-reload")
	g.restarted(t)
	confined := decoded(t, await(t, g.invocation, "native_probe", 10*time.Second))
	if err := os.Remove(filepath.Join(overrides, "probe.conf")); err != nil {
		t.Fatal(err)
	}
	run(t, "systemctl", "daemon-reload")
	if confined.User != g.uid || confined.Checks["descriptors of process 1"] != allowed || confined.Checks["memory of process 1"] != "EPERM" || confined.Mounts["/proc"] != "ro" {
		t.Errorf("with the drop-in the agent's account lists the descriptors of process 1 as %q, reads its memory as %q, finds /proc %s",
			confined.Checks["descriptors of process 1"], confined.Checks["memory of process 1"], confined.Mounts["/proc"])
	}
	if granted := await(t, g.invocation, "agent_privileges", 30*time.Second); granted["level"] != "INFO" || fmt.Sprint(granted["capabilities"]) != "[CAP_DAC_READ_SEARCH CAP_SYS_PTRACE]" {
		t.Errorf("with the drop-in and the network module enabled, the agent reported %v", granted)
	}
	g.networked(t, "network_observed")
	hold(t, heldUnit, installed, "listen tcp4 127.0.0.1:47005")
	named := g.listener(t, "listener_opened", "127.0.0.1", 47005)
	if fmt.Sprint(named["processes"]) != "[native.test (pid "+propertyOf(t, heldUnit, "MainPID")+")]" || named["association"] != "processes" {
		t.Errorf("a listener whose process the agent may name was said as %v", named)
	}
	hold(t, nestedUnit, installed, "listen tcp4 127.0.0.1:47006", "--property=NetworkNamespacePath=/proc/"+isolated+"/ns/net")
	nested := g.listener(t, "listener_opened", "127.0.0.1", 47006)
	identity, err := os.Readlink(filepath.Join("/proc", isolated, "ns", "net"))
	if err != nil {
		t.Fatal(err)
	}
	if namespace, _ := nested["namespace"].(map[string]any); namespace["id"] != identity || fmt.Sprint(nested["processes"]) != "[native.test (pid "+propertyOf(t, nestedUnit, "MainPID")+")]" {
		t.Errorf("a listener in the namespace %s was said as %v", identity, nested)
	}
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "network_not_covered" {
			t.Errorf("seeing every process and its descriptors, the agent said %v", entry)
		}
	}
	g.statusSays(t, true, "\nmodule network: running")

	g.listening, g.debugging = false, false
	g.collecting(t, g.collects)
	if stopped := await(t, g.invocation, "module_stopped", 30*time.Second); stopped["module"] != "network" {
		t.Errorf("the agent stopped %v", stopped)
	}
	if err := os.Remove(filepath.Join(overrides, networkDropIn)); err != nil {
		t.Fatal(err)
	}
	run(t, "systemctl", "daemon-reload")
	g.restarted(t)
}

// hold starts a copy of the gate as nobody, in a unit of its own, holding the
// sockets it is given, and waits until it holds them.
func hold(t *testing.T, name, installed, sockets string, properties ...string) {
	t.Helper()
	arguments := append([]string{"--unit=" + name, "--property=Type=exec", "--property=User=nobody", "--setenv=" + socketsVariable + "=" + sockets}, properties...)
	run(t, "systemd-run", append(arguments, installed)...)
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(answer("journalctl", "--no-pager", "--output", "cat", "--unit", name), "holding") {
		if time.Now().After(deadline) {
			t.Fatalf("%s holds nothing:\n%s", name, answer("journalctl", "--no-pager", "--unit", name))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func propertyOf(t *testing.T, unit, name string) string {
	t.Helper()
	return strings.TrimSpace(run(t, "systemctl", "show", "--property", name, "--value", unit))
}

// networked waits for the network module to log a message in the invocation
// running now, and returns the latest one.
func (g *gate) networked(t *testing.T, message string) map[string]any {
	t.Helper()
	return g.awaitNetwork(t, time.Minute, func(entry map[string]any) bool { return entry["msg"] == message })
}

func (g *gate) listener(t *testing.T, message, address string, port float64) map[string]any {
	t.Helper()
	return g.awaitNetwork(t, time.Minute, func(entry map[string]any) bool {
		return entry["msg"] == message && entry["address"] == address && entry["port"] == port
	})
}

func (g *gate) flow(t *testing.T, message, direction, remote string, port float64) map[string]any {
	t.Helper()
	return g.awaitNetwork(t, 90*time.Second, func(entry map[string]any) bool {
		return entry["msg"] == message && entry["direction"] == direction && entry["remote"] == remote && entry["port"] == port
	})
}

func (g *gate) saidOf(t *testing.T, message, address string, port float64) map[string]any {
	t.Helper()
	for _, entry := range journal(t, g.invocation) {
		if entry["module"] == "network" && entry["msg"] == message && entry["address"] == address && entry["port"] == port {
			return entry
		}
	}
	return nil
}

func (g *gate) awaitNetwork(t *testing.T, within time.Duration, wanted func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		found := slices.DeleteFunc(journal(t, g.invocation), func(entry map[string]any) bool { return entry["module"] != "network" || !wanted(entry) })
		if len(found) > 0 {
			return found[len(found)-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("the network module did not log what was awaited:\n%s", answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// rounds waits for the network module to read the sockets of the host count
// times more than it has in the invocation running now.
func (g *gate) rounds(t *testing.T, count int) {
	t.Helper()
	observed := func() int {
		return len(slices.DeleteFunc(journal(t, g.invocation), func(entry map[string]any) bool { return entry["msg"] != "network_observed" }))
	}
	want := observed() + count
	deadline := time.Now().Add(time.Minute)
	for observed() < want {
		if time.Now().After(deadline) {
			t.Fatalf("the network module read the sockets %d times, want %d", observed(), want)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
