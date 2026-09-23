package governor

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"
)

// Critical work that waits is served first, and bulk work waiting behind it
// is served once this many critical grants in a row have passed it over, so
// a steady stream of critical work delays bulk work and never starves it.
const favoured = 4

const minBurst = 64 << 10

// Waking a goroutine costs the processor far more than the bytes a short wait
// pays for, so a wait for the budget lasts at least a step: saturated work
// wakes at most fifty times a second, and what it saved up serves what follows.
const step = 20 * time.Millisecond

type waiter struct {
	module  string
	class   Class
	ready   chan struct{}
	granted bool
}

type queue struct {
	waiting []*waiter
	streak  int
}

func (q *queue) add(w *waiter) { q.waiting = append(q.waiting, w) }

func (q *queue) remove(w *waiter) {
	q.waiting = slices.DeleteFunc(q.waiting, func(held *waiter) bool { return held == w })
}

// The waiter to serve next, and whether a bulk waiter could have been served
// in its place. A rank orders the waiters of one class, lowest first, and
// arrival breaks ties; without one, each class is served in arrival order.
func (q *queue) next(bulk bool, rank func(*waiter) int) (*waiter, bool) {
	critical := q.first(Critical, rank)
	var passed *waiter
	if bulk {
		passed = q.first(Bulk, rank)
	}
	if critical != nil && (passed == nil || q.streak < favoured) {
		return critical, passed != nil
	}
	return passed, false
}

func (q *queue) first(class Class, rank func(*waiter) int) *waiter {
	var chosen *waiter
	for _, held := range q.waiting {
		if held.class != class {
			continue
		}
		if chosen == nil || (rank != nil && rank(held) < rank(chosen)) {
			chosen = held
		}
	}
	return chosen
}

func (q *queue) served(w *waiter, passed bool) {
	q.remove(w)
	switch {
	case w.class == Bulk:
		q.streak = 0
	case passed:
		q.streak++
	}
}

type pool struct {
	mu       sync.Mutex
	capacity int
	reserved int
	held     map[Class]int
	modules  map[string]int
	queue    queue
}

func newPool() *pool { return &pool{held: map[Class]int{}, modules: map[string]int{}} }

func (p *pool) limit(capacity, reserved int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.capacity, p.reserved = capacity, reserved
	p.dispatch()
}

func (p *pool) acquire(ctx context.Context, module string, class Class) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w := &waiter{module: module, class: class, ready: make(chan struct{})}
	p.mu.Lock()
	p.queue.add(w)
	p.dispatch()
	p.mu.Unlock()
	select {
	case <-w.ready:
	case <-ctx.Done():
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		if w.granted {
			p.put(w)
		} else {
			p.queue.remove(w)
		}
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.put(w)
		})
	}, nil
}

func (p *pool) dispatch() {
	for p.held[Critical]+p.held[Bulk] < p.capacity {
		w, passed := p.queue.next(p.held[Bulk] < p.capacity-p.reserved, p.rank)
		if w == nil {
			return
		}
		p.queue.served(w, passed)
		p.held[w.class]++
		p.modules[w.module]++
		w.granted = true
		close(w.ready)
	}
}

func (p *pool) rank(w *waiter) int { return p.modules[w.module] }

func (p *pool) put(w *waiter) {
	p.held[w.class]--
	if p.modules[w.module]--; p.modules[w.module] <= 0 {
		delete(p.modules, w.module)
	}
	p.dispatch()
}

func (p *pool) use() Use {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Use{Critical: p.held[Critical], Bulk: p.held[Bulk], Waiting: len(p.queue.waiting)}
}

type pace struct {
	mu      sync.Mutex
	rate    float64
	burst   int64
	tokens  float64
	updated time.Time
	queue   queue
}

func (p *pace) limit(rate int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.rate == 0 {
		p.tokens, p.updated = float64(burst(rate)), now
	}
	p.refill(now)
	p.rate, p.burst = float64(rate), burst(rate)
	p.tokens = min(p.tokens, float64(p.burst))
	p.nudge()
}

func burst(rate int64) int64 { return max(rate/8, minBurst) }

func (p *pace) largest() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.burst
}

func (p *pace) take(ctx context.Context, class Class, want int64) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	w := &waiter{class: class, ready: make(chan struct{}, 1)}
	p.mu.Lock()
	p.queue.add(w)
	for {
		p.refill(time.Now())
		need := min(want, p.burst)
		head, passed := p.queue.next(true, nil)
		if head == w && p.tokens >= float64(need) {
			p.tokens -= float64(need)
			p.queue.served(w, passed)
			p.nudge()
			p.mu.Unlock()
			return need, nil
		}
		var due <-chan time.Time
		var timer *time.Timer
		if head == w {
			missing := time.Duration(math.Ceil((float64(need) - p.tokens) / p.rate * float64(time.Second)))
			timer = time.NewTimer(max(missing, step))
			due = timer.C
		}
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			stop(timer)
			p.mu.Lock()
			p.queue.remove(w)
			p.nudge()
			p.mu.Unlock()
			return 0, ctx.Err()
		case <-due:
		case <-w.ready:
			stop(timer)
		}
		p.mu.Lock()
	}
}

func (p *pace) refill(now time.Time) {
	if elapsed := now.Sub(p.updated); elapsed > 0 {
		p.tokens = min(float64(p.burst), p.tokens+p.rate*elapsed.Seconds())
	}
	p.updated = now
}

func (p *pace) nudge() {
	if head, _ := p.queue.next(true, nil); head != nil {
		select {
		case head.ready <- struct{}{}:
		default:
		}
	}
}

func (p *pace) waiting() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue.waiting)
}

func stop(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}
