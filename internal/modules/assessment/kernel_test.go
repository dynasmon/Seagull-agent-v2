package assessment

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sysctl"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func TestAKernelParameterIsJudgedByTheValueInForce(t *testing.T) {
	host := newHost()
	host.parameters["kernel.cad_pid"] = ""
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"forwarding off": {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Allowed: []string{"0"}},
			answered{pass, `net.ipv4.ip_forward is "0"`}},
		"randomization full": {&assessmentv1.KernelParameterTest{Name: "kernel.randomize_va_space", Allowed: []string{"1"}},
			answered{fail, `kernel.randomize_va_space is "2", which is none of 1`}},
		"a range with spaces": {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_local_port_range", Allowed: []string{"32768 60999"}},
			answered{pass, `"32768 60999"`}},
		"at least one": {&assessmentv1.KernelParameterTest{Name: "kernel.yama.ptrace_scope", AtLeast: proto.Int64(1)},
			answered{pass, `kernel.yama.ptrace_scope is "1"`}},
		"at most one": {&assessmentv1.KernelParameterTest{Name: "kernel.randomize_va_space", AtMost: proto.Int64(1)},
			answered{fail, "above 1"}},
		"bounds on a range": {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_local_port_range", AtLeast: proto.Int64(1024)},
			answered{fail, "which is not one integer"}},
		"absent where present only": {&assessmentv1.KernelParameterTest{Name: "net.ipv6.conf.all.accept_ra", Allowed: []string{"0"}},
			answered{inapplicable, "the kernel has no parameter net.ipv6.conf.all.accept_ra"}},
		"absent and required": {&assessmentv1.KernelParameterTest{Name: "kernel.yama.ptrace_policy", Presence: required, AtLeast: proto.Int64(1)},
			answered{fail, "the kernel has no parameter kernel.yama.ptrace_policy"}},
		"present and forbidden": {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Presence: forbidden},
			answered{fail, `net.ipv4.ip_forward is "0"`}},
		"not named as sysctl names": {&assessmentv1.KernelParameterTest{Name: "net/../../etc", Allowed: []string{"0"}},
			answered{unsupported, "its parameter is not named as sysctl names one"}},
	})

	denied := newHost()
	denied.failing["parameters"] = fmt.Errorf("%w: kernel.cad_pid", sysctl.ErrDenied)
	expect(t, denied, map[string]struct {
		test any
		want answered
	}{
		"only root reads it": {&assessmentv1.KernelParameterTest{Name: "kernel.cad_pid", Presence: required}, answered{erred, "the agent's account may not read kernel.cad_pid"}},
	})
}

func TestAKernelModuleIsJudgedByWhatTheKernelHoldsAndWhatModprobeWouldDo(t *testing.T) {
	host := newHost()
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"cramfs kept out": {&assessmentv1.KernelModuleTest{Name: "cramfs", Loaded: forbidden, Disabled: true},
			answered{pass, "cramfs is not loaded; /etc/modprobe.d/cramfs.conf line 1 has modprobe run \"/bin/false\" for it; /etc/modprobe.d/cramfs.conf line 2 blacklists it"}},
		"usb storage loaded on demand": {&assessmentv1.KernelModuleTest{Name: "usb-storage", Disabled: true},
			answered{fail, "line 2 has modprobe run \"/sbin/modprobe --ignore-install usb_storage\" for it, which does not keep it out"}},
		"squashfs never kept out": {&assessmentv1.KernelModuleTest{Name: "squashfs", Disabled: true},
			answered{fail, "no install line of the modprobe configuration keeps squashfs out"}},
		"tls loaded": {&assessmentv1.KernelModuleTest{Name: "tls", Loaded: forbidden},
			answered{fail, "tls is loaded"}},
		"vt built in": {&assessmentv1.KernelModuleTest{Name: "vt", Loaded: forbidden},
			answered{fail, "vt is built into the kernel"}},
		"tls required": {&assessmentv1.KernelModuleTest{Name: "tls", Loaded: required},
			answered{pass, "tls is loaded"}},
		"udf required": {&assessmentv1.KernelModuleTest{Name: "udf", Loaded: required},
			answered{fail, "udf is not loaded"}},
		"judging nothing": {&assessmentv1.KernelModuleTest{Name: "udf"},
			answered{unsupported, "it judges nothing of the module"}},
	})
	if host.reads["modprobe"] != 1 || host.reads["modules"] != 1 {
		t.Fatalf("one round read the modprobe configuration %d times and the kernel's modules %d times", host.reads["modprobe"], host.reads["modules"])
	}

	unread := newHost()
	unread.failing["modprobe"] = errors.New("/etc/modprobe.d/private.conf: permission denied")
	expect(t, unread, map[string]struct {
		test any
		want answered
	}{
		"cramfs kept out": {&assessmentv1.KernelModuleTest{Name: "cramfs", Disabled: true}, answered{erred, "the modprobe configuration cannot be read"}},
	})
}
