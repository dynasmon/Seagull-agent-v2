// Package status keeps what the running agent says of itself where somebody on
// the endpoint can read it: one snapshot of every part of the agent, what state
// each is in and what to do about it, written again as the agent runs and read
// without disturbing it. A snapshot holds what the agent's log already says,
// bounded, and nothing that authenticates the agent.
package status

import (
	"errors"
	"time"
	"unicode/utf8"
)

const (
	Format   = 1
	name     = "status.json"
	maxBytes = 256 << 10
	maxText  = 1 << 10
	cut      = "..."
)

var (
	ErrUnwritten = errors.New("the agent has written no status")
	ErrDamaged   = errors.New("the status cannot be read")
	ErrNewer     = errors.New("the status was written by a newer agent")
	ErrInsecure  = errors.New("the status is not private to the account the agent runs as")
)

type State string

const (
	Running  State = "running"
	Degraded State = "degraded"
	Failed   State = "failed"
	Disabled State = "disabled"
	Stopped  State = "stopped"
)

func (s State) rank() int {
	switch s {
	case Failed:
		return 3
	case Degraded:
		return 2
	case Running:
		return 1
	}
	return 0
}

// Text is what a snapshot says in words: a reason, what to do, a name. However
// long what it was made from, it is written as a kilobyte at most.
type Text string

func (t Text) MarshalText() ([]byte, error) {
	held := string(t)
	if len(held) <= maxText {
		return []byte(held), nil
	}
	held = held[:maxText]
	for range utf8.UTFMax - 1 {
		if last, width := utf8.DecodeLastRuneInString(held); last != utf8.RuneError || width > 1 {
			break
		}
		held = held[:len(held)-1]
	}
	return []byte(held + cut), nil
}

type Snapshot struct {
	Format       int         `json:"format"`
	WrittenAt    time.Time   `json:"written_at"`
	EverySeconds int         `json:"every_seconds"`
	State        State       `json:"state"`
	Reason       Text        `json:"reason,omitempty"`
	Agent        Agent       `json:"agent"`
	Components   []Component `json:"components"`
	Modules      []Module    `json:"modules"`
	Streams      []Stream    `json:"streams"`
	Listeners    []Listener  `json:"listeners"`
	Credential   *Credential `json:"credential,omitempty"`
	Resources    Resources   `json:"resources"`
}

type Agent struct {
	Build          Text      `json:"build"`
	Process        int       `json:"process"`
	StartedAt      time.Time `json:"started_at"`
	InstallationID Text      `json:"installation_id"`
	AgentID        Text      `json:"agent_id,omitempty"`
}

type Component struct {
	Name     Text      `json:"name"`
	State    State     `json:"state"`
	Since    time.Time `json:"since,omitzero"`
	Reason   Text      `json:"reason,omitempty"`
	Recovery Text      `json:"recovery,omitempty"`
}

type Module struct {
	Name     Text      `json:"name"`
	State    State     `json:"state"`
	Since    time.Time `json:"since,omitzero"`
	Restarts int       `json:"restarts"`
	Reason   Text      `json:"reason,omitempty"`
}

type Stream struct {
	Stream        Text      `json:"stream"`
	Outstanding   uint64    `json:"outstanding"`
	Bytes         int64     `json:"bytes"`
	Oldest        time.Time `json:"oldest,omitzero"`
	LastDelivered time.Time `json:"last_delivered,omitzero"`
	Delivered     uint64    `json:"delivered"`
	Expired       uint64    `json:"expired"`
	Lost          uint64    `json:"lost"`
	Quarantined   uint64    `json:"quarantined"`
	Refused       uint64    `json:"refused"`
	PausedSince   time.Time `json:"paused_since,omitzero"`
	FailingSince  time.Time `json:"failing_since,omitzero"`
	Attempts      int       `json:"attempts,omitempty"`
	Outcome       Text      `json:"outcome,omitempty"`
	Failure       Text      `json:"failure,omitempty"`
	NextAttempt   time.Time `json:"next_attempt,omitzero"`
}

type Listener struct {
	Name         Text      `json:"name"`
	Answered     time.Time `json:"answered,omitzero"`
	FailingSince time.Time `json:"failing_since,omitzero"`
	Failure      Text      `json:"failure,omitempty"`
	Attempts     int       `json:"attempts,omitempty"`
	NextAttempt  time.Time `json:"next_attempt,omitzero"`
}

type Credential struct {
	AgentID      Text      `json:"agent_id"`
	Generation   uint64    `json:"generation"`
	Serial       Text      `json:"serial"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	RenewsAt     time.Time `json:"renews_at,omitzero"`
	Renewed      time.Time `json:"renewed,omitzero"`
	FailingSince time.Time `json:"failing_since,omitzero"`
	Attempts     int       `json:"attempts,omitempty"`
	Failure      Text      `json:"failure,omitempty"`
	NextAttempt  time.Time `json:"next_attempt,omitzero"`
}

type Resources struct {
	MemoryHeld    int64 `json:"memory_held"`
	MemoryLimit   int64 `json:"memory_limit"`
	MemoryCeiling int64 `json:"memory_ceiling,omitempty"`
	Goroutines    int   `json:"goroutines"`
	Uploads       Use   `json:"uploads"`
	Scans         Use   `json:"scans"`
	DeferredScans int   `json:"deferred_scans"`
}

type Use struct {
	Held    int `json:"held"`
	Waiting int `json:"waiting"`
	Limit   int `json:"limit"`
}

// Worst is the state of the agent as a whole: that of its worst part, where a
// part nothing asked for weighs nothing.
func Worst(components []Component) State {
	worst := Running
	for _, component := range components {
		if component.State.rank() > worst.rank() {
			worst = component.State
		}
	}
	return worst
}

// Fresh says whether the agent was still writing its status at now: it had not
// said it stopped, and it wrote the snapshot within three of its intervals.
func (s Snapshot) Fresh(now time.Time) bool {
	every := time.Duration(max(s.EverySeconds, 1)) * time.Second
	return s.State != Stopped && now.Sub(s.WrittenAt) <= 3*every
}
