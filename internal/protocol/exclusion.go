package protocol

import (
	"fmt"

	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type Reason int

const (
	Unidentified Reason = iota + 1
	Unregistered
	Unadmitted
)

func (r Reason) String() string {
	switch r {
	case Unidentified:
		return "unidentified"
	case Unregistered:
		return "unregistered"
	case Unadmitted:
		return "unadmitted"
	default:
		return fmt.Sprintf("reason(%d)", int(r))
	}
}

// The platform names the agent by the certificate it verified, and refuses the
// agent itself when that certificate names no agent it can read, an agent it
// never registered, or one it no longer admits: revoked, decommissioned or
// disabled. The records of such a batch are not at fault.
var excluding = map[string]Reason{
	"unauthenticated_agent": Unidentified,
	"agent_not_registered":  Unregistered,
	"agent_not_admitted":    Unadmitted,
}

// An Exclusion is the platform refusing the agent rather than anything a batch
// carried, whatever record the refusal points at: every record stays as valid
// as it was, none of them is delivered while the exclusion lasts, and none of
// them is to be quarantined for it.
type Exclusion struct {
	Reason Reason
	Detail string
}

func (e *Exclusion) Error() string {
	return fmt.Sprintf("the platform refuses this agent, %s: %s", e.Reason, e.Detail)
}

func Excluded(refusal *ingestv1.Rejection) (*Exclusion, bool) {
	reason, excluded := excluding[refusal.GetCode()]
	if !excluded {
		return nil, false
	}
	return &Exclusion{Reason: reason, Detail: refusal.GetDetail()}, true
}
