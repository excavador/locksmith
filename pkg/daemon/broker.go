package daemon

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/excavador/locksmith/pkg/wire"
)

type (
	// Broker is the daemon's in-process pub/sub fan-out for wire.Event.
	// Topics are arbitrary strings; the daemon uses "vault:<name>" and
	// "job:<id>" topic naming, but the broker itself is generic.
	//
	// Each topic keeps a small ring buffer of recent events so that a
	// subscriber that joins after a publish still sees the recent history
	// (last DefaultRingSize events by default). Slow consumers must not
	// block publishers: if a subscriber's channel is full, the event is
	// dropped for that subscriber and a debug message is logged.
	Broker struct {
		logger *slog.Logger

		mu     sync.RWMutex
		topics map[string]*topicState

		nextID atomic.Uint64
	}

	// topicState holds the per-topic ring buffer and subscriber list.
	topicState struct {
		mu      sync.Mutex
		ring    []*wire.Event // size cap = ringCap
		ringCap int
		subs    map[uint64]chan *wire.Event
	}
)

const (
	// DefaultRingSize is the per-topic ring buffer length used when a
	// subscriber does not request an explicit one. Old enough to let a
	// late subscriber catch up on a typical job, small enough to bound
	// daemon memory in the face of many topics.
	DefaultRingSize = 64
)

// NewBroker constructs an empty Broker. Logger is used for slow-subscriber
// drop warnings; pass slog.Default() if you don't have one handy.
func NewBroker(logger *slog.Logger) *Broker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Broker{
		logger: logger,
		topics: make(map[string]*topicState),
	}
}

// Subscribe attaches a new subscriber to the given topic. The returned
// channel receives events as they are published; bufSize controls the
// channel's buffer (a slow subscriber whose channel is full will have
// events dropped). The unsubscribe function detaches the subscriber and
// closes the channel; safe to call multiple times.
//
// Any events currently in the topic's ring buffer are replayed into the
// new subscriber's channel before any new events are forwarded. The
// replay respects bufSize (oldest entries are dropped if the buffer can't
// hold them all), so a subscriber that asks for bufSize=1 just gets the
// most recent event plus future ones.
func (b *Broker) Subscribe(topic string, bufSize int) (subID uint64, ch <-chan *wire.Event, unsubscribe func()) {
	if bufSize < 1 {
		bufSize = 1
	}

	b.mu.Lock()
	state, ok := b.topics[topic]
	if !ok {
		state = &topicState{
			ringCap: DefaultRingSize,
			subs:    make(map[uint64]chan *wire.Event),
		}
		b.topics[topic] = state
	}
	b.mu.Unlock()

	out := make(chan *wire.Event, bufSize)
	id := b.nextID.Add(1)

	state.mu.Lock()
	// Replay ring (best-effort: drop oldest if out of buffer space).
	for _, evt := range state.ring {
		select {
		case out <- evt:
		default:
			// Buffer full during replay — drop the oldest queued and try once more.
			select {
			case <-out:
			default:
			}
			select {
			case out <- evt:
			default:
			}
		}
	}
	state.subs[id] = out
	state.mu.Unlock()

	var once sync.Once
	unsub := func() {
		once.Do(func() {
			state.mu.Lock()
			if _, exists := state.subs[id]; exists {
				delete(state.subs, id)
				close(out)
			}
			state.mu.Unlock()
		})
	}

	return id, out, unsub
}

// Publish appends evt to the topic's ring buffer (evicting the oldest if
// at capacity) and fans it out to every current subscriber on the topic.
// Subscribers whose channels are full have the event dropped (logged at
// debug level). Publish never blocks on a slow subscriber.
func (b *Broker) Publish(topic string, evt *wire.Event) {
	if evt == nil {
		return
	}

	b.mu.RLock()
	state, ok := b.topics[topic]
	b.mu.RUnlock()
	if !ok {
		// No subscribers yet — still want to record the event in a fresh
		// topic so a future Subscribe can replay it.
		b.mu.Lock()
		state, ok = b.topics[topic]
		if !ok {
			state = &topicState{
				ringCap: DefaultRingSize,
				subs:    make(map[uint64]chan *wire.Event),
			}
			b.topics[topic] = state
		}
		b.mu.Unlock()
	}

	state.mu.Lock()
	// Append to ring; evict oldest if at cap.
	if len(state.ring) >= state.ringCap {
		copy(state.ring, state.ring[1:])
		state.ring[len(state.ring)-1] = evt
	} else {
		state.ring = append(state.ring, evt)
	}
	// Fan out to subscribers.
	for id, ch := range state.subs {
		select {
		case ch <- evt:
		default:
			b.logger.DebugContext(context.Background(), "broker slow subscriber drop",
				slog.String("topic", topic),
				slog.Uint64("sub_id", id),
			)
		}
	}
	state.mu.Unlock()
}

// CloseAll closes every subscriber channel and clears all topics. Used
// during daemon shutdown to signal in-flight Subscribe RPCs that the
// stream is over.
func (b *Broker) CloseAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, state := range b.topics {
		state.mu.Lock()
		for id, ch := range state.subs {
			delete(state.subs, id)
			close(ch)
		}
		state.mu.Unlock()
	}
}
