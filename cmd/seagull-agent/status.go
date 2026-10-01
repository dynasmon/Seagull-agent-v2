package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/delivery"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/authentication"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/ceilings"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

// What the running agent says of itself, read off the components it composed:
// each one's state and, when it is not running as it should, why and what to
// do about it, in the words the agent's log uses. Nothing here reads a key or
// a certificate, only what the installation records about them.
type observing struct {
	began          time.Time
	path           string
	state          string
	installation   *identity.Installation
	spool          *spool.Spool
	governor       *governor.Governor
	configuration  *configuration
	collection     *modules.Collection
	authentication *authentication.Collector
	renewer        *renewal.Renewer
	delivery       *delivery.Delivery
}

func (o *observing) snapshot() status.Snapshot {
	now := time.Now()
	snapshot := status.Snapshot{Agent: status.Agent{
		Build:          status.Text(buildIdentity()),
		Process:        os.Getpid(),
		StartedAt:      o.began.UTC(),
		InstallationID: status.Text(o.installation.ID()),
	}}
	active, enrolled := o.installation.Enrollment()
	if enrolled {
		snapshot.Agent.AgentID = status.Text(active.AgentID)
	}
	spooled := o.streams(&snapshot)
	delivering := o.delivered(&snapshot, enrolled)
	snapshot.Components = []status.Component{
		o.configuration.observed(),
		o.collected(&snapshot),
		spooled,
		delivering,
		o.credential(&snapshot, active, enrolled, now),
		o.resources(&snapshot),
	}
	return snapshot
}

func (c *configuration) observed() status.Component {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refused == nil {
		return status.Component{Name: "configuration", State: status.Running, Since: c.applied.UTC()}
	}
	return status.Component{
		Name:     "configuration",
		State:    status.Degraded,
		Since:    c.refusedAt.UTC(),
		Reason:   status.Text(fmt.Sprintf("the agent runs on the configuration it applied at %s, and refused what %s holds now: %v", c.applied.UTC().Format(time.RFC3339), c.path, c.refused)),
		Recovery: status.Text(c.hint),
	}
}

func (o *observing) collected(snapshot *status.Snapshot) status.Component {
	component := status.Component{Name: "collection", State: status.Disabled, Reason: "no module is enabled"}
	for _, module := range o.collection.Health() {
		held := status.Module{Name: status.Text(module.Name), State: kept(module.State), Since: module.Since.UTC(), Restarts: module.Restarts, Reason: status.Text(module.Reason)}
		state := held.State
		switch {
		case module.State == modules.Degraded && module.Reason == "":
			held.Reason, state = "the agent has not started it yet", status.Running
		case module.Name == authentication.Name && module.State == modules.Running:
			held.Reason = status.Text(o.reading())
		}
		snapshot.Modules = append(snapshot.Modules, held)
		switch {
		case state == status.Disabled:
		case component.State == status.Disabled, component.State == status.Running && state != status.Running, component.State == status.Degraded && state == status.Failed:
			component = status.Component{Name: "collection", State: state}
			if state != status.Running {
				component.Since, component.Reason = held.Since, status.Text(fmt.Sprintf("%s: %s", module.Name, module.Reason))
			}
			switch state {
			case status.Degraded:
				component.Recovery = "none: the agent starts the module again"
			case status.Failed:
				component.Recovery = status.Text("correct what the module reports, then name it again in modules of " + o.path + " and have the agent read its configuration again")
			}
		}
	}
	return component
}

func kept(held modules.State) status.State {
	switch held {
	case modules.Running:
		return status.Running
	case modules.Degraded:
		return status.Degraded
	case modules.Failed:
		return status.Failed
	}
	return status.Disabled
}

func (o *observing) reading() string {
	held := o.authentication.Stats()
	var said []string
	if !held.Waiting.IsZero() {
		said = append(said, fmt.Sprintf("waiting since %s for room in the spool, while what sshd decides waits in the journal", held.Waiting.UTC().Format(time.RFC3339)))
	}
	if held.Gaps > 0 {
		said = append(said, fmt.Sprintf("since the agent started, the journal dropped entries before the collector read them %d times, as collection_gap in its log says", held.Gaps))
	}
	if held.Aged > 0 {
		said = append(said, fmt.Sprintf("%d outcomes were older than the platform admits when the collector read them", held.Aged))
	}
	return strings.Join(said, "; ")
}

func (o *observing) streams(snapshot *status.Snapshot) status.Component {
	component := status.Component{Name: "spool", State: status.Running}
	for _, held := range o.spool.Stats().Streams {
		snapshot.Streams = append(snapshot.Streams, status.Stream{
			Stream:      status.Text(held.Stream.String()),
			Outstanding: held.Outstanding,
			Bytes:       held.Bytes,
			Delivered:   held.Delivered,
			Expired:     held.Expired,
			Lost:        held.Lost,
			Quarantined: held.Quarantined,
			Refused:     held.Refused,
			PausedSince: held.Paused.UTC(),
		})
		switch {
		case held.Unavailable != nil:
			component = status.Component{Name: "spool", State: status.Failed, Reason: status.Text(fmt.Sprintf("%s: %v", held.Stream, held.Unavailable)),
				Recovery: status.Text(recovery(o.path, o.state, held.Unavailable))}
		case !held.Paused.IsZero() && component.State == status.Running:
			component = status.Component{Name: "spool", State: status.Degraded, Since: held.Paused.UTC(),
				Reason: status.Text(fmt.Sprintf("the spool holds all its budget allows for %s, and refused %d records since %s: a collector that could not admit them keeps its place in its source, and what the source drops meanwhile is a gap",
					held.Stream, held.Refused, held.Paused.UTC().Format(time.RFC3339))),
				Recovery: status.Text("none while the platform takes what the spool holds; for a longer outage, raise spool.max_bytes in " + o.path)}
		}
	}
	return component
}

func (o *observing) delivered(snapshot *status.Snapshot, enrolled bool) status.Component {
	if o.delivery == nil {
		reason := "the installation is not enrolled, so nothing it admits is delivered"
		if enrolled {
			reason = "the installation was enrolled after the agent started, and it delivers once it starts again"
		}
		return status.Component{Name: "delivery", State: status.Degraded, Reason: status.Text(reason), Recovery: status.Text(recovery(o.path, o.state, renewal.ErrNotEnrolled))}
	}
	held := o.delivery.Stats()
	listener := held.Listener
	snapshot.Listeners = append(snapshot.Listeners, status.Listener{Name: status.Text(listener.Listener), Answered: listener.Answered.UTC(), FailingSince: listener.Failing.UTC(),
		Attempts: listener.Attempts, NextAttempt: listener.Next.UTC()})
	component := status.Component{Name: "delivery", State: status.Running}
	if !listener.Failing.IsZero() {
		snapshot.Listeners[0].Failure = status.Text(listener.Failure.String())
		component = status.Component{Name: "delivery", State: status.Degraded, Since: listener.Failing.UTC(), Reason: status.Text(listener.Reason), Recovery: status.Text(listener.Recovery)}
	}
	for _, route := range held.Routes {
		for i := range snapshot.Streams {
			kept := &snapshot.Streams[i]
			if string(kept.Stream) != route.Stream.String() {
				continue
			}
			kept.Oldest, kept.LastDelivered = route.Oldest.UTC(), route.Delivered.UTC()
			if route.Failing.IsZero() {
				continue
			}
			kept.FailingSince, kept.Attempts, kept.Outcome, kept.NextAttempt = route.Failing.UTC(), route.Attempts, status.Text(route.Outcome.String()), route.Next.UTC()
			if route.Failure != 0 {
				kept.Failure = status.Text(route.Failure.String())
			}
			if component.State == status.Running {
				component = status.Component{Name: "delivery", State: status.Degraded, Since: route.Failing.UTC(),
					Reason: status.Text(fmt.Sprintf("%s: %s", route.Stream, route.Reason)), Recovery: status.Text(route.Recovery)}
			}
		}
	}
	return component
}

func (o *observing) credential(snapshot *status.Snapshot, active identity.Enrollment, enrolled bool, now time.Time) status.Component {
	if !enrolled {
		return status.Component{Name: "credential", State: status.Disabled, Reason: "the installation is not enrolled"}
	}
	certificate := active.Certificate
	held := &status.Credential{AgentID: status.Text(active.AgentID), Generation: active.Generation, Serial: status.Text(certificate.Serial),
		NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC()}
	snapshot.Credential = held
	var renewing renewal.State
	if o.renewer != nil {
		renewing = o.renewer.State()
		held.RenewsAt, held.Renewed, held.FailingSince, held.Attempts, held.NextAttempt = renewing.RenewsAt.UTC(), renewing.Renewed.UTC(), renewing.Failing.UTC(), renewing.Attempts, renewing.Next.UTC()
		if renewing.Failure != 0 {
			held.Failure = status.Text(renewing.Failure.String())
		}
	}
	switch {
	case !now.Before(certificate.NotAfter):
		return status.Component{Name: "credential", State: status.Failed, Since: certificate.NotAfter.UTC(),
			Reason:   status.Text(fmt.Sprintf("the certificate of credential generation %d expired at %s, so nothing is delivered and nothing renews it", active.Generation, certificate.NotAfter.UTC().Format(time.RFC3339))),
			Recovery: status.Text(recovery(o.path, o.state, renewal.ErrExpired))}
	case now.Before(certificate.NotBefore):
		return status.Component{Name: "credential", State: status.Degraded,
			Reason:   status.Text(fmt.Sprintf("the certificate of credential generation %d is valid from %s, and the clock of this host says %s", active.Generation, certificate.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))),
			Recovery: "correct the clock of this host, which is behind the platform's"}
	case !renewing.Failing.IsZero():
		return status.Component{Name: "credential", State: status.Degraded, Since: renewing.Failing.UTC(), Reason: status.Text(renewing.Reason), Recovery: status.Text(renewing.Recovery)}
	}
	return status.Component{Name: "credential", State: status.Running}
}

func (o *observing) resources(snapshot *status.Snapshot) status.Component {
	settings := o.configuration.active.Settings()
	samples := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(samples)
	var held int64
	if samples[0].Value.Kind() == metrics.KindUint64 && samples[1].Value.Kind() == metrics.KindUint64 {
		held = int64(samples[0].Value.Uint64() - samples[1].Value.Uint64())
	}
	governed := o.governor.Stats()
	spent := status.Resources{
		MemoryHeld:    held,
		MemoryLimit:   int64(settings.Resources.MemoryLimit),
		Goroutines:    runtime.NumGoroutine(),
		Uploads:       status.Use{Held: governed.Uploads.Critical + governed.Uploads.Bulk, Waiting: governed.Uploads.Waiting, Limit: governed.Budget.Uploads},
		Scans:         status.Use{Held: governed.Scans.Critical + governed.Scans.Bulk, Waiting: governed.Scans.Waiting, Limit: governed.Budget.Scans},
		DeferredScans: governed.Deferred,
	}
	if enforced, err := ceilings.Enforced(); err == nil {
		spent.MemoryCeiling = enforced.Memory
	}
	snapshot.Resources = spent
	if held > spent.MemoryLimit {
		return status.Component{Name: "resources", State: status.Degraded,
			Reason:   status.Text(fmt.Sprintf("the agent holds %d bytes, more than the %s resources.memory_limit sets, so the garbage collector works without reaching it", held, config.Size(spent.MemoryLimit))),
			Recovery: status.Text("raise resources.memory_limit in " + o.path + ", below the memory the service that runs the agent lets it hold")}
	}
	return status.Component{Name: "resources", State: status.Running}
}

func report(path string, stdout, stderr io.Writer) int {
	settings, err := config.Load(path)
	if err != nil {
		return refuse(path, "", err, stderr)
	}
	state := settings.Identity.StateDirectory
	held, err := status.Read(filepath.Join(state, statusDirectory))
	if err != nil {
		return refuse(path, state, err, stderr)
	}
	now := time.Now()
	if err := held.Print(stdout, now); err != nil {
		return refuse(path, state, err, stderr)
	}
	if held.State == status.Running && held.Fresh(now) {
		return 0
	}
	return 1
}
