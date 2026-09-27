// Package delivery sends what the spool holds to the platform, one batch at a
// time on each route, and settles every record by what the platform answered:
// as delivered once a durable acknowledgement of the whole batch is written
// down, as quarantined once the platform refuses the record for good, and not
// at all otherwise, so the record is sent again.
package delivery

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math"
	mathrand "math/rand/v2"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

const (
	jitter     = 0.2
	widest     = 1 << 16
	resending  = "none: the agent sends the batch again, with the same records, until the platform acknowledges them"
	rewriting  = "none: the agent writes it down again, and sends the records again if it stops first"
	unreadable = "none: a record the agent cannot read as one its route carries could never be delivered, so it is counted as quarantined"
)

type Spool interface {
	Read(stream spool.Stream, from uint64, most, bytes int) ([]spool.Entry, error)
	Acknowledge(stream spool.Stream, sequences ...uint64) error
	Quarantine(stream spool.Stream, reason string, sequences ...uint64) error
	Admitted(stream spool.Stream) <-chan struct{}
}

type Client interface {
	Post(ctx context.Context, request transport.Request) (transport.Reply, error)
}

type Batching struct {
	MaxBytes            int
	MaxEvents           int
	MaxInventoryRecords int
}

// A Policy bounds how soon a batch is sent again: Retry after the first
// failure the network or a busy platform explains, doubling up to
// RetryLongest; Hold after the first one that waits on somebody, or on the
// clocks, to change something, doubling up to HoldLongest. A zero field takes
// the documented value.
type Policy struct {
	Retry        time.Duration
	RetryLongest time.Duration
	Hold         time.Duration
	HoldLongest  time.Duration
}

func (p Policy) settled() (Policy, error) {
	fields := []struct {
		held  *time.Duration
		value time.Duration
	}{{&p.Retry, time.Second}, {&p.RetryLongest, 5 * time.Minute}, {&p.Hold, time.Minute}, {&p.HoldLongest, time.Hour}}
	for _, field := range fields {
		switch {
		case *field.held < 0:
			return Policy{}, fmt.Errorf("a delivery policy of %+v waits a negative time", p)
		case *field.held == 0:
			*field.held = field.value
		}
	}
	if p.RetryLongest < p.Retry || p.HoldLongest < p.Hold {
		return Policy{}, fmt.Errorf("a delivery policy of %+v waits less after failing again than it waits first", p)
	}
	return p, nil
}

func (p Policy) wait(failures int, lasting bool) time.Duration {
	first, longest := p.Retry, p.RetryLongest
	if lasting {
		first, longest = p.Hold, p.HoldLongest
	}
	wait := min(float64(first)*math.Pow(2, float64(max(failures, 1)-1)), float64(longest))
	return time.Duration(wait * (1 - jitter + 2*jitter*mathrand.Float64()))
}

type Options struct {
	Spool    Spool
	Client   Client
	Governor *governor.Governor
	URL      string
	Batching func() Batching
	Policy   Policy
	Logger   *slog.Logger
	Recovery func(error) string
}

type Delivery struct {
	routes []*route
}

func New(options Options) (*Delivery, error) {
	var problems []error
	if options.Spool == nil || options.Client == nil || options.Governor == nil || options.Batching == nil || options.Logger == nil {
		problems = append(problems, errors.New("a spool, a transport, a governor, batch limits and a logger are all needed to deliver"))
	}
	target, err := url.Parse(options.URL)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" {
		problems = append(problems, errors.New("the ingest listener is an https address with a host"))
	}
	policy, err := options.Policy.settled()
	if err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the delivery: %w", errors.Join(problems...))
	}
	options.Policy = policy
	if options.Recovery == nil {
		options.Recovery = func(error) string { return "" }
	}
	delivery := &Delivery{}
	for _, carried := range []struct {
		stream spool.Stream
		route  protocol.Route
		class  governor.Class
	}{{spool.Events, protocol.Events, governor.Critical}, {spool.Inventory, protocol.Inventory, governor.Bulk}} {
		address := *target
		address.Path += carried.route.Path()
		delivery.routes = append(delivery.routes, &route{
			options: options, stream: carried.stream, protocol: carried.route, class: carried.class, url: address.String(), next: 1,
		})
	}
	return delivery, nil
}

// Run delivers both routes until ctx ends, each on its own, so a route the
// platform does not take holds back nothing on the other. It returns early
// only when the spool it delivers from is gone.
func (d *Delivery) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var failed []error
	var running sync.WaitGroup
	for _, delivering := range d.routes {
		running.Go(func() {
			if err := delivering.run(ctx); err != nil {
				mu.Lock()
				failed = append(failed, err)
				mu.Unlock()
				cancel()
			}
		})
	}
	running.Wait()
	return errors.Join(failed...)
}

type entry struct {
	sequence uint64
	id       string
	admitted time.Time
	record   []byte
}

type batch struct {
	id      string
	entries []entry
	body    []byte
	sent    int
}

func (b *batch) sequences() []uint64 {
	sequences := make([]uint64, len(b.entries))
	for i, carried := range b.entries {
		sequences[i] = carried.sequence
	}
	return sequences
}

type route struct {
	options  Options
	stream   spool.Stream
	protocol protocol.Route
	class    governor.Class
	url      string

	next     uint64
	pending  *batch
	window   int
	failures int
	failing  time.Time
	until    time.Time
}

func (r *route) run(ctx context.Context) error {
	for ctx.Err() == nil {
		if r.pending == nil {
			admitted := r.options.Spool.Admitted(r.stream)
			composed, err := r.compose()
			switch {
			case errors.Is(err, spool.ErrClosed):
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("deliver %s: %w", r.stream, err)
			case err != nil:
				r.failed()
				wait := r.options.Policy.wait(r.failures, false)
				r.options.Logger.Error("delivery_not_read", r.attributes(slog.Any("error", err), slog.Int("attempt", r.failures),
					slog.Time("next_attempt", time.Now().Add(wait)), slog.String("recovery", "none: the agent reads the spool again"))...)
				if !sleep(ctx, wait) {
					return nil
				}
				continue
			case composed == nil:
				select {
				case <-ctx.Done():
				case <-admitted:
				}
				continue
			}
			r.pending, r.until = composed, time.Time{}
		}
		if !sleep(ctx, time.Until(r.until)) {
			return nil
		}
		if err := r.deliver(ctx, r.pending); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("deliver %s: %w", r.stream, err)
		}
	}
	return nil
}

func (r *route) compose() (*batch, error) {
	limits := r.options.Batching()
	most := limits.MaxEvents
	if r.stream == spool.Inventory {
		most = limits.MaxInventoryRecords
	}
	if r.window > 0 {
		most = min(most, r.window)
	}
	id := draw()
	room := limits.MaxBytes - r.protocol.Envelope(id)
	for {
		read, err := r.options.Spool.Read(r.stream, r.next, max(most, 1), max(room, 1))
		if err != nil || len(read) == 0 {
			return nil, err
		}
		var entries []entry
		framed, items := 0, 0
		r.next = read[len(read)-1].Sequence + 1
		for i, held := range read {
			identity, err := r.protocol.Identify(held.Payload)
			if err == nil && identity.ID != held.ID {
				err = fmt.Errorf("it was admitted as %s and carries the identifier %s", secrets.Shown(held.ID), secrets.Shown(identity.ID))
			}
			if err != nil {
				if err := r.options.Spool.Quarantine(r.stream, err.Error(), held.Sequence); err != nil {
					r.next = held.Sequence
					return nil, err
				}
				r.options.Logger.Warn("record_not_delivered", r.attributes(slog.Uint64("sequence", held.Sequence), slog.String("record_id", secrets.Shown(held.ID)),
					slog.Any("error", err), slog.String("recovery", unreadable))...)
				continue
			}
			size := r.protocol.Framed(len(held.Payload))
			if len(entries) > 0 && (framed+size > room || items+identity.Items > protocol.MaxInventoryItemsPerBatch) {
				r.next = read[i].Sequence
				break
			}
			entries = append(entries, entry{sequence: held.Sequence, id: held.ID, admitted: held.Admitted, record: held.Payload})
			framed, items = framed+size, items+identity.Items
		}
		if len(entries) > 0 {
			return r.frame(id, entries), nil
		}
	}
}

func (r *route) frame(id string, entries []entry) *batch {
	entries = slices.Clone(entries)
	records := make([][]byte, len(entries))
	for i, carried := range entries {
		records[i] = carried.record
	}
	body := r.protocol.Batch(id, records)
	for i, record := range r.protocol.Records(body) {
		entries[i].record = record
	}
	return &batch{id: id, entries: entries, body: body}
}

func (r *route) deliver(ctx context.Context, sent *batch) error {
	sent.sent++
	reply, err := r.send(ctx, sent)
	if err := ctx.Err(); err != nil {
		return err
	}
	verdict := r.judge(sent, reply, err)
	switch verdict.Outcome {
	case protocol.Durable:
		if err := r.settle(ctx, sent, "acknowledgement", func() error { return r.options.Spool.Acknowledge(r.stream, sent.sequences()...) }); err != nil {
			return err
		}
		r.delivered(sent)
	case protocol.RecordRefused:
		return r.refuse(ctx, sent, verdict.Record, verdict.Reason)
	case protocol.BatchTooLarge, protocol.BatchUndecodable:
		if len(sent.entries) == 1 {
			return r.refuse(ctx, sent, 0, verdict.Reason)
		}
		r.split(sent, verdict)
	default:
		r.retry(sent, verdict)
	}
	return nil
}

func (r *route) send(ctx context.Context, sent *batch) (transport.Reply, error) {
	var reply transport.Reply
	err := r.options.Governor.Upload(ctx, r.class, func(ctx context.Context, meter *governor.Meter) error {
		sending, stop := context.WithCancel(ctx)
		defer stop()
		var err error
		reply, err = r.options.Client.Post(sending, transport.Request{
			URL:         r.url,
			ContentType: protocol.ContentType,
			Body:        meter.Reader(sending, bytes.NewReader(sent.body)),
			Length:      int64(len(sent.body)),
		})
		return err
	})
	return reply, err
}

func (r *route) judge(sent *batch, reply transport.Reply, err error) protocol.Verdict {
	switch {
	case errors.Is(err, transport.ErrUnreachable):
		return protocol.Verdict{Outcome: protocol.Unconfirmed, Record: -1, Reason: err}
	case err != nil:
		return protocol.Verdict{Outcome: protocol.Unexpected, Record: -1, Reason: err}
	}
	carried := make([]protocol.Sent, len(sent.entries))
	for i, held := range sent.entries {
		carried[i] = protocol.Sent{Record: held.record, Admitted: held.admitted}
	}
	return r.protocol.Judge(carried, protocol.Answer{Status: reply.Status, ContentType: reply.ContentType, Body: reply.Body, Date: reply.Date})
}

func (r *route) delivered(sent *batch) {
	if r.failures > 0 {
		r.options.Logger.Info("delivery_resumed", r.attributes(slog.String("batch_id", sent.id), slog.Int("attempts", r.failures),
			slog.Duration("failing", time.Since(r.failing)))...)
	}
	r.options.Logger.Debug("batch_delivered", r.attributes(slog.String("batch_id", sent.id), slog.Int("records", len(sent.entries)),
		slog.Int("bytes", len(sent.body)), slog.Int("attempts", sent.sent))...)
	r.pending, r.until, r.failures = nil, time.Time{}, 0
	if r.window > 0 {
		r.window = min(2*r.window, widest)
	}
}

// A refusal of one record says the records before it passed what the platform
// checks, since it checks them in order and stops at the first it refuses; the
// ones after it were never looked at. So those before are sent again at once
// as a batch of their own, and those after in batches half as large as the one
// that carried the refused record, until the platform takes a batch whole.
func (r *route) refuse(ctx context.Context, sent *batch, index int, reason error) error {
	refused := sent.entries[index]
	if err := r.settle(ctx, sent, "quarantine", func() error {
		return r.options.Spool.Quarantine(r.stream, reason.Error(), refused.sequence)
	}); err != nil {
		return err
	}
	r.options.Logger.Warn("record_refused", r.attributes(slog.String("batch_id", sent.id), slog.Uint64("sequence", refused.sequence),
		slog.String("record_id", secrets.Shown(refused.id)), slog.Any("error", reason),
		slog.String("recovery", "none: the platform refuses the record for good, so it is counted as quarantined rather than delivered"))...)
	r.pending, r.until = nil, time.Time{}
	r.window = max(len(sent.entries)/2, 1)
	if index > 0 {
		r.pending = r.frame(draw(), sent.entries[:index])
	}
	if index+1 < len(sent.entries) {
		r.next = min(r.next, sent.entries[index+1].sequence)
	}
	return nil
}

func (r *route) split(sent *batch, verdict protocol.Verdict) {
	half := len(sent.entries) / 2
	r.options.Logger.Warn("batch_split", r.attributes(slog.String("batch_id", sent.id), slog.Int("records", len(sent.entries)),
		slog.Int("bytes", len(sent.body)), slog.String("outcome", verdict.Outcome.String()), slog.Any("error", verdict.Reason),
		slog.String("recovery", "none: the agent sends the records again in batches half as large, and quarantines a record the platform refuses alone"))...)
	r.window = max(half, 1)
	r.pending, r.until = r.frame(draw(), sent.entries[:half]), time.Time{}
	r.next = min(r.next, sent.entries[half].sequence)
}

func (r *route) failed() {
	r.failures++
	if r.failures == 1 {
		r.failing = time.Now()
	}
}

func (r *route) retry(sent *batch, verdict protocol.Verdict) {
	r.failed()
	lasting := verdict.Outcome != protocol.Unconfirmed
	wait := r.options.Policy.wait(r.failures, lasting)
	r.until = time.Now().Add(wait)
	level, recovery := slog.LevelWarn, resending
	if lasting {
		level, recovery = slog.LevelError, r.options.Recovery(verdict.Reason)
	}
	attributes := r.attributes(slog.String("batch_id", sent.id), slog.Int("records", len(sent.entries)),
		slog.Uint64("first", sent.entries[0].sequence), slog.Uint64("last", sent.entries[len(sent.entries)-1].sequence),
		slog.String("outcome", verdict.Outcome.String()))
	if verdict.Record >= 0 {
		held := sent.entries[verdict.Record]
		attributes = append(attributes, slog.Uint64("sequence", held.sequence), slog.String("record_id", secrets.Shown(held.id)))
	}
	r.options.Logger.Log(context.Background(), level, "delivery_failed", append(attributes, slog.Any("error", verdict.Reason),
		slog.Int("attempt", r.failures), slog.Time("next_attempt", r.until), slog.String("recovery", recovery))...)
}

func (r *route) settle(ctx context.Context, sent *batch, what string, settle func() error) error {
	for attempt := 1; ; attempt++ {
		err := settle()
		if err == nil || errors.Is(err, spool.ErrClosed) {
			return err
		}
		wait := r.options.Policy.wait(attempt, false)
		r.options.Logger.Error("delivery_not_settled", r.attributes(slog.String("batch_id", sent.id), slog.String("settling", what),
			slog.Int("records", len(sent.entries)), slog.Any("error", err), slog.Int("attempt", attempt),
			slog.Time("next_attempt", time.Now().Add(wait)), slog.String("recovery", rewriting))...)
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
	}
}

func (r *route) attributes(extra ...any) []any {
	return append([]any{slog.String("stream", r.stream.String())}, extra...)
}

func sleep(ctx context.Context, wait time.Duration) bool {
	if wait <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func draw() string {
	drawn := make([]byte, 16)
	rand.Read(drawn)
	drawn[6] = drawn[6]&0x0f | 0x40
	drawn[8] = drawn[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", drawn[0:4], drawn[4:6], drawn[6:8], drawn[8:10], drawn[10:])
}
