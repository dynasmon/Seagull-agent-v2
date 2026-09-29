package status

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Print writes the snapshot as somebody who reads it at now takes it in: what
// state the agent is in and since when, what each part of it does and what to
// do about the ones that do not run, then what it holds and has not delivered,
// what it keeps of each listener, its credential and what it spends. What the
// agent could not keep of what its sources hold is said apart from what it
// keeps and could not deliver.
func (s Snapshot) Print(w io.Writer, now time.Time) error {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	written := stamp(s.WrittenAt) + ", " + ago(now, s.WrittenAt)
	switch {
	case s.State == Stopped:
		line("the agent stopped: its status was written %s: %s", written, shown(s.Reason))
	case !s.Fresh(now):
		line("the agent last wrote its status %s, and writes it every %ds: it stopped without saying so, or cannot write its status; it was %s then", written, s.EverySeconds, s.State)
	default:
		line("the agent is %s: its status was written %s", s.State, written)
	}
	agent := "an installation that is not enrolled"
	if s.Agent.AgentID != "" {
		agent = "agent " + shown(s.Agent.AgentID)
	}
	line("%s, installation %s, process %d started %s", agent, shown(s.Agent.InstallationID), s.Agent.Process, stamp(s.Agent.StartedAt))
	line("%s", shown(s.Agent.Build))
	line("")
	for _, component := range s.Components {
		said := shown(component.Name) + ": " + string(component.State)
		if !component.Since.IsZero() {
			said += " since " + stamp(component.Since)
		}
		if component.Reason != "" {
			said += ": " + shown(component.Reason)
		}
		line("%s", said)
		if component.Recovery != "" && component.State != Running {
			line("  what to do: %s", shown(component.Recovery))
		}
	}
	for _, module := range s.Modules {
		said := fmt.Sprintf("module %s: %s since %s, started again %s", shown(module.Name), module.State, stamp(module.Since), counted(module.Restarts, "time"))
		if module.Reason != "" {
			said += ": " + shown(module.Reason)
		}
		line("%s", said)
	}
	line("")
	for _, stream := range s.Streams {
		s.stream(line, stream, now)
	}
	for _, listener := range s.Listeners {
		said := shown(listener.Name) + " listener: answering"
		if !listener.FailingSince.IsZero() {
			said = fmt.Sprintf("%s listener: failing since %s, %s, %s; next attempt %s", shown(listener.Name), stamp(listener.FailingSince),
				shown(listener.Failure), counted(listener.Attempts, "attempt"), ago(now, listener.NextAttempt))
		}
		if !listener.Answered.IsZero() {
			said += "; last answered " + ago(now, listener.Answered)
		}
		line("%s", said)
	}
	if held := s.Credential; held != nil {
		line("credential: agent %s, generation %d, serial %s, valid from %s until %s", shown(held.AgentID), held.Generation, shown(held.Serial), stamp(held.NotBefore), stamp(held.NotAfter))
		switch {
		case !held.FailingSince.IsZero():
			line("  renewal failing since %s, %s, %s; next attempt %s", stamp(held.FailingSince), shown(held.Failure), counted(held.Attempts, "attempt"), ago(now, held.NextAttempt))
		case !held.RenewsAt.IsZero():
			line("  renews %s", ago(now, held.RenewsAt))
		}
		if !held.Renewed.IsZero() {
			line("  last renewed %s", ago(now, held.Renewed))
		}
	}
	spent := s.Resources
	ceiling := ""
	if spent.MemoryCeiling > 0 {
		ceiling = " within a ceiling of " + size(spent.MemoryCeiling)
	}
	line("resources: %s of memory held, for a target of %s%s; %d goroutines", size(spent.MemoryHeld), size(spent.MemoryLimit), ceiling, spent.Goroutines)
	line("  uploads: %d of %d held, %d waiting; scans: %d of %d held, %d waiting, %d deferred", spent.Uploads.Held, spent.Uploads.Limit, spent.Uploads.Waiting,
		spent.Scans.Held, spent.Scans.Limit, spent.Scans.Waiting, spent.DeferredScans)
	_, err := io.WriteString(w, b.String())
	return err
}

func (s Snapshot) stream(line func(string, ...any), stream Stream, now time.Time) {
	waiting := "nothing waiting"
	if stream.Outstanding > 0 {
		waiting = fmt.Sprintf("%s waiting in %s", counted(int(stream.Outstanding), "record"), size(stream.Bytes))
		if !stream.Oldest.IsZero() {
			waiting += ", the oldest admitted " + ago(now, stream.Oldest)
		}
	}
	delivered := "nothing delivered since the agent started"
	if !stream.LastDelivered.IsZero() {
		delivered = "last delivered " + ago(now, stream.LastDelivered)
	}
	line("%s: %s; %s", shown(stream.Stream), waiting, delivered)
	line("  kept: %d delivered, %d expired, %d lost, %d quarantined", stream.Delivered, stream.Expired, stream.Lost, stream.Quarantined)
	if stream.Refused > 0 || !stream.PausedSince.IsZero() {
		paused := ""
		if !stream.PausedSince.IsZero() {
			paused = ", admitting nothing since " + stamp(stream.PausedSince)
		}
		line("  not kept: %s refused admission%s", counted(int(stream.Refused), "record"), paused)
	}
	if !stream.FailingSince.IsZero() {
		line("  failing since %s: %s, %s, %s; next attempt %s", stamp(stream.FailingSince), counted(stream.Attempts, "attempt"), shown(stream.Outcome), shown(stream.Failure), ago(now, stream.NextAttempt))
	}
}

func counted(count int, what string) string {
	if count == 1 {
		return "1 " + what
	}
	return strconv.Itoa(count) + " " + what + "s"
}

func stamp(at time.Time) string {
	if at.IsZero() {
		return "an unknown moment"
	}
	return at.UTC().Format(time.RFC3339)
}

func ago(now, at time.Time) string {
	if at.IsZero() {
		return "at an unknown moment"
	}
	if gone := now.Sub(at); gone >= 0 {
		return spell(gone) + " ago"
	}
	return "in " + spell(at.Sub(now))
}

func spell(span time.Duration) string {
	if span >= 48*time.Hour {
		return strconv.FormatInt(int64(span/(24*time.Hour)), 10) + " days"
	}
	return span.Round(time.Second).String()
}

func size(bytes int64) string {
	for _, unit := range []struct {
		name  string
		scale int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if bytes >= unit.scale {
			return strconv.FormatFloat(float64(bytes)/float64(unit.scale), 'f', 1, 64) + unit.name
		}
	}
	return strconv.FormatInt(bytes, 10) + "B"
}

func shown(text Text) string {
	held := string(text)
	if held == "" {
		return "none"
	}
	if utf8.ValidString(held) && strings.IndexFunc(held, func(held rune) bool { return !unicode.IsPrint(held) }) < 0 {
		return held
	}
	return strconv.Quote(held)
}
