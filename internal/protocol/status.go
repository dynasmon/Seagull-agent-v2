package protocol

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// What the platform admits of a status report beyond the shape of its
// contract: an interval it can judge lateness against, a bounded number of
// parts, modules, streams, groups and capabilities, and every text within the
// length its gateway checks.
const (
	MinStatusInterval     = 10 * time.Second
	MaxStatusInterval     = time.Hour
	MaxStatusText         = 1 << 10
	MaxStatusVersion      = 128
	MaxStatusName         = 64
	MaxStatusParts        = 32
	MaxStatusStreams      = 8
	MaxStatusGroups       = 64
	MaxStatusCapabilities = 64
)

const (
	maxBootID        = 64
	maxStatusRelease = 128
	maxRevision      = 64
	maxToolchain     = 32
	maxTarget        = 32
	maxPolicyID      = 64
	maxAccount       = 64
	maxCapability    = 32
	maxSeccomp       = 32
	maxIdentifier    = 64
	cutMark          = "..."
	sha256HexBytes   = 64
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// Cut keeps text within most bytes, cutting it on a character and saying so
// with an ellipsis, so a reason never makes a report one the platform refuses.
func Cut(text string, most int) string {
	if len(text) <= most {
		return text
	}
	if most <= len(cutMark) {
		return cutMark[:max(most, 0)]
	}
	kept := text[:most-len(cutMark)]
	for !utf8.ValidString(kept) {
		kept = kept[:len(kept)-1]
	}
	return kept + cutMark
}

// CheckStatus refuses what the platform would refuse of a report whatever
// moment it reached it, naming the field as the platform names it.
func CheckStatus(report *agentv1.Status) error {
	run, build, spool, configuration, privileges := report.GetRun(), report.GetBuild(), report.GetSpool(), report.GetConfiguration(), report.GetPrivileges()
	interval := report.GetInterval().AsDuration()
	switch {
	case report.GetSchemaVersion() != StatusSchemaVersion:
		return &Inadmissible{Field: "schema_version", Reason: fmt.Sprintf("is not %d", StatusSchemaVersion)}
	case !identifier.MatchString(report.GetInstallationId()) || len(report.GetInstallationId()) > maxIdentifier:
		return &Inadmissible{Field: "installation_id", Reason: "is missing or malformed"}
	case report.GetSequence() == 0:
		return &Inadmissible{Field: "sequence", Reason: "is missing"}
	case !report.GetReportedAt().IsValid():
		return &Inadmissible{Field: "reported_at", Reason: "is not a moment"}
	case !report.GetInterval().IsValid() || interval < MinStatusInterval || interval > MaxStatusInterval:
		return &Inadmissible{Field: "interval", Reason: fmt.Sprintf("is not between %s and %s", MinStatusInterval, MaxStatusInterval)}
	case run == nil || !run.GetStartedAt().IsValid():
		return &Inadmissible{Field: "run.started_at", Reason: "is not a moment"}
	case build == nil:
		return &Inadmissible{Field: "build", Reason: "is missing"}
	case spool == nil:
		return &Inadmissible{Field: "spool", Reason: "is missing"}
	case configuration == nil || !digest(configuration.GetDigestSha256()):
		return &Inadmissible{Field: "configuration.digest_sha256", Reason: "is not a lowercase hex SHA-256"}
	case privileges == nil:
		return &Inadmissible{Field: "privileges", Reason: "is missing"}
	case len(report.GetComponents()) > MaxStatusParts:
		return &Inadmissible{Field: "components", Reason: fmt.Sprintf("carries more than %d components", MaxStatusParts)}
	case len(report.GetModules()) > MaxStatusParts:
		return &Inadmissible{Field: "modules", Reason: fmt.Sprintf("carries more than %d modules", MaxStatusParts)}
	case len(spool.GetStreams()) > MaxStatusStreams:
		return &Inadmissible{Field: "spool.streams", Reason: fmt.Sprintf("carries more than %d streams", MaxStatusStreams)}
	case len(privileges.GetGroups()) > MaxStatusGroups:
		return &Inadmissible{Field: "privileges.groups", Reason: fmt.Sprintf("carries more than %d groups", MaxStatusGroups)}
	case len(privileges.GetCapabilities()) > MaxStatusCapabilities:
		return &Inadmissible{Field: "privileges.capabilities", Reason: fmt.Sprintf("carries more than %d capabilities", MaxStatusCapabilities)}
	}
	host := report.GetOrigin().GetHost()
	checks := []error{
		text("origin.host.hostname", host.GetHostname(), maxHostname, false),
		text("origin.host.os", host.GetOs(), maxOperatingSystem, false),
		text("origin.host.architecture", host.GetArchitecture(), maxArchitecture, false),
		text("run.boot_id", run.GetBootId(), maxBootID, false),
		text("run.previous_reason", run.GetPreviousReason(), MaxStatusText, false),
		enumerated("run.previous_ending", agentv1.Status_Ending_name[int32(run.GetPreviousEnding())]),
		moment("run.previous_seen_at", run.GetPreviousSeenAt() == nil || run.GetPreviousSeenAt().IsValid()),
		text("build.version", build.GetVersion(), maxStatusRelease, true),
		text("build.revision", build.GetRevision(), maxRevision, false),
		text("build.toolchain", build.GetToolchain(), maxToolchain, false),
		text("build.os", build.GetOs(), maxTarget, false),
		text("build.architecture", build.GetArchitecture(), maxTarget, false),
		condition("condition", report.GetCondition()),
		text("configuration.policy_id", configuration.GetPolicyId(), maxPolicyID, false),
		moment("configuration.policy_expires_at", configuration.GetPolicyExpiresAt() == nil || configuration.GetPolicyExpiresAt().IsValid()),
		text("privileges.user", privileges.GetUser(), maxAccount, true),
		text("privileges.seccomp", privileges.GetSeccomp(), maxSeccomp, false),
	}
	if credential := report.GetCredential(); credential != nil {
		checks = append(checks,
			moment("credential.not_after", credential.GetNotAfter().IsValid()),
			moment("credential.renews_at", credential.GetRenewsAt() == nil || credential.GetRenewsAt().IsValid()),
			moment("credential.renewal_failing_since", credential.GetRenewalFailingSince() == nil || credential.GetRenewalFailingSince().IsValid()))
	}
	for index, part := range report.GetComponents() {
		checks = append(checks, named(fmt.Sprintf("components[%d]", index), part.GetName(), part.GetCondition(), part.GetSince(), part.GetReason()))
	}
	for index, module := range report.GetModules() {
		checks = append(checks, named(fmt.Sprintf("modules[%d]", index), module.GetName(), module.GetCondition(), module.GetSince(), module.GetReason()))
	}
	for index, stream := range spool.GetStreams() {
		field := fmt.Sprintf("spool.streams[%d]", index)
		checks = append(checks, text(field+".name", stream.GetName(), MaxStatusName, true))
		for name, at := range map[string]*timestamppb.Timestamp{"oldest_admitted": stream.GetOldestAdmitted(), "last_delivered": stream.GetLastDelivered(),
			"paused_since": stream.GetPausedSince(), "failing_since": stream.GetFailingSince()} {
			checks = append(checks, moment(field+"."+name, at == nil || at.IsValid()))
		}
	}
	for index, group := range privileges.GetGroups() {
		checks = append(checks, text(fmt.Sprintf("privileges.groups[%d]", index), group, maxAccount, true))
	}
	for index, capability := range privileges.GetCapabilities() {
		checks = append(checks, text(fmt.Sprintf("privileges.capabilities[%d]", index), capability, maxCapability, true))
	}
	return firstOf(checks...)
}

func named(field, name string, state agentv1.Status_Condition, since *timestamppb.Timestamp, reason string) error {
	return firstOf(
		text(field+".name", name, MaxStatusName, true),
		condition(field+".condition", state),
		moment(field+".since", since == nil || since.IsValid()),
		text(field+".reason", reason, MaxStatusText, false))
}

func condition(field string, state agentv1.Status_Condition) error {
	if state == agentv1.Status_CONDITION_UNSPECIFIED {
		return &Inadmissible{Field: field, Reason: "is unspecified"}
	}
	return enumerated(field, agentv1.Status_Condition_name[int32(state)])
}

func digest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == sha256HexBytes && strings.ToLower(value) == value && len(decoded) == sha256HexBytes/2
}
