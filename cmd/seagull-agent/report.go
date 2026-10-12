package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const maxHostname = 255

var conditions = map[status.State]agentv1.Status_Condition{
	status.Running:  agentv1.Status_CONDITION_RUNNING,
	status.Degraded: agentv1.Status_CONDITION_DEGRADED,
	status.Failed:   agentv1.Status_CONDITION_FAILED,
	status.Disabled: agentv1.Status_CONDITION_DISABLED,
	status.Stopped:  agentv1.Status_CONDITION_STOPPED,
}

var endings = map[status.Ending]agentv1.Status_Ending{
	status.EndingNone:        agentv1.Status_ENDING_NONE,
	status.EndingStopped:     agentv1.Status_ENDING_STOPPED,
	status.EndingInterrupted: agentv1.Status_ENDING_INTERRUPTED,
}

// What the agent tells the platform of itself: what its status says, in the
// words of the contract, each one cut to what the platform takes. The reporter
// stamps the sequence, the moment and the interval as it sends it.
func (o *observing) report(stopping bool) *agentv1.Status {
	held := o.snapshot()
	state := status.Worst(held.Components)
	if stopping {
		state = status.Stopped
	}
	report := &agentv1.Status{
		SchemaVersion:  protocol.StatusSchemaVersion,
		InstallationId: string(held.Agent.InstallationID),
		Origin:         &eventv1.Origin{Host: &eventv1.Host{Hostname: hostname(), Os: runtime.GOOS, Architecture: runtime.GOARCH}},
		Run:            &agentv1.Status_Run{BootId: string(held.Agent.Boot), StartedAt: timestamppb.New(o.began)},
		Build:          built(),
		Condition:      conditions[state],
		Spool:          &agentv1.Status_Spool{},
		Configuration:  &agentv1.Status_Configuration{DigestSha256: string(held.Agent.Configuration)},
		Privileges:     &agentv1.Status_Privileges{},
	}
	if previous := held.Agent.Previous; previous != nil {
		report.Run.PreviousEnding, report.Run.PreviousReason = endings[previous.Ending], protocol.Cut(string(previous.Reason), protocol.MaxStatusText)
		if !previous.SeenAt.IsZero() {
			report.Run.PreviousSeenAt = timestamppb.New(previous.SeenAt)
		}
	}
	for _, component := range held.Components[:min(len(held.Components), protocol.MaxStatusParts)] {
		report.Components = append(report.Components, &agentv1.Status_Component{Name: protocol.Cut(string(component.Name), protocol.MaxStatusName),
			Condition: conditions[component.State], Since: moment(component.Since), Reason: protocol.Cut(string(component.Reason), protocol.MaxStatusText)})
	}
	for _, module := range held.Modules[:min(len(held.Modules), protocol.MaxStatusParts)] {
		report.Modules = append(report.Modules, &agentv1.Status_Module{Name: protocol.Cut(string(module.Name), protocol.MaxStatusName),
			Condition: conditions[module.State], Since: moment(module.Since), Restarts: uint32(max(module.Restarts, 0)), Reason: protocol.Cut(string(module.Reason), protocol.MaxStatusText)})
	}
	spooled := o.spool.Stats()
	report.Spool.Bytes, report.Spool.MaxBytes = uint64(max(spooled.Bytes, 0)), uint64(max(spooled.MaxBytes, 0))
	for _, stream := range held.Streams[:min(len(held.Streams), protocol.MaxStatusStreams)] {
		report.Spool.Streams = append(report.Spool.Streams, &agentv1.Status_Stream{
			Name: protocol.Cut(string(stream.Stream), protocol.MaxStatusName), Outstanding: stream.Outstanding, Bytes: uint64(max(stream.Bytes, 0)),
			OldestAdmitted: moment(stream.Oldest), LastDelivered: moment(stream.LastDelivered), PausedSince: moment(stream.PausedSince), FailingSince: moment(stream.FailingSince),
			Delivered: stream.Delivered, Expired: stream.Expired, Lost: stream.Lost, Quarantined: stream.Quarantined,
		})
	}
	if credential := held.Credential; credential != nil {
		report.Credential = &agentv1.Status_Credential{Generation: credential.Generation, NotAfter: timestamppb.New(credential.NotAfter),
			RenewsAt: moment(credential.RenewsAt), RenewalFailingSince: moment(credential.FailingSince)}
	}
	if id, revision, expires := o.configuration.inForce(); revision > 0 {
		report.Configuration.PolicyId, report.Configuration.PolicyRevision, report.Configuration.PolicyExpiresAt = id, revision, timestamppb.New(expires)
	}
	if granted := held.Agent.Privileges; granted != nil {
		report.Privileges.User, report.Privileges.NoNewPrivileges = strconv.Itoa(granted.User), granted.NoNewPrivs
		report.Privileges.Seccomp = protocol.Cut(string(granted.Seccomp), 32)
		for _, group := range granted.Groups[:min(len(granted.Groups), protocol.MaxStatusGroups)] {
			report.Privileges.Groups = append(report.Privileges.Groups, strconv.Itoa(group))
		}
		for _, capability := range granted.Capabilities[:min(len(granted.Capabilities), protocol.MaxStatusCapabilities)] {
			report.Privileges.Capabilities = append(report.Privileges.Capabilities, protocol.Cut(string(capability), 32))
		}
	}
	return report
}

func moment(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() {
		return nil
	}
	return timestamppb.New(at)
}

func hostname() string {
	named, err := os.Hostname()
	if err != nil {
		return ""
	}
	return protocol.Cut(named, maxHostname)
}

func built() *agentv1.Status_Build {
	build := &agentv1.Status_Build{Version: "(devel)", Toolchain: runtime.Version(), Os: runtime.GOOS, Architecture: runtime.GOARCH}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return build
	}
	if info.Main.Version != "" {
		build.Version = protocol.Cut(info.Main.Version, 128)
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			build.Revision = protocol.Cut(setting.Value, 64)
		}
	}
	return build
}

// The digest of the settings in force, as the agent encodes them: it names a
// change between two reports, never what changed.
func digested(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
