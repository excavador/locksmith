package daemon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/excavador/locksmith/pkg/wire"
)

func quietBrokerLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestBrokerSubscribePublishReceive(t *testing.T) {
	b := NewBroker(quietBrokerLogger())

	_, ch, unsub := b.Subscribe("vault:foo", 4)
	defer unsub()

	evt := &wire.Event{Kind: wire.EventKindStateChanged, Message: "hi"}
	b.Publish("vault:foo", evt)

	select {
	case got := <-ch:
		if got.Message != "hi" {
			t.Errorf("got Message=%q", got.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBrokerMultipleSubscribersFanOut(t *testing.T) {
	b := NewBroker(quietBrokerLogger())

	_, ch1, unsub1 := b.Subscribe("vault:foo", 4)
	defer unsub1()
	_, ch2, unsub2 := b.Subscribe("vault:foo", 4)
	defer unsub2()

	b.Publish("vault:foo", &wire.Event{Message: "x"})

	for i, ch := range []<-chan *wire.Event{ch1, ch2} {
		select {
		case got := <-ch:
			if got.Message != "x" {
				t.Errorf("sub %d: got %q", i, got.Message)
			}
		case <-time.After(time.Second):
			t.Fatalf("sub %d: timed out", i)
		}
	}
}

func TestBrokerSlowSubscriberDrops(t *testing.T) {
	b := NewBroker(quietBrokerLogger())

	// Very small buffer; don't consume, verify publisher doesn't block.
	_, _, unsub := b.Subscribe("vault:foo", 1)
	defer unsub()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			b.Publish("vault:foo", &wire.Event{Message: "x"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on slow subscriber")
	}
}

func TestBrokerRingReplayOnLateSubscribe(t *testing.T) {
	b := NewBroker(quietBrokerLogger())

	// Publish with no subscribers — should still be recorded in the ring.
	for i := 0; i < 3; i++ {
		b.Publish("vault:foo", &wire.Event{Message: "buffered"})
	}

	_, ch, unsub := b.Subscribe("vault:foo", 8)
	defer unsub()

	received := 0
	deadline := time.After(500 * time.Millisecond)
	for received < 3 {
		select {
		case <-ch:
			received++
		case <-deadline:
			t.Fatalf("only got %d replayed events, want 3", received)
		}
	}
}

func TestBrokerUnsubscribeClosesChannel(t *testing.T) {
	b := NewBroker(quietBrokerLogger())
	_, ch, unsub := b.Subscribe("vault:foo", 4)
	unsub()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("channel should be closed after unsubscribe")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed")
	}
}

func TestBrokerCloseAllClosesAllSubscribers(t *testing.T) {
	b := NewBroker(quietBrokerLogger())
	_, ch1, _ := b.Subscribe("a", 1)
	_, ch2, _ := b.Subscribe("b", 1)

	b.CloseAll()

	for i, ch := range []<-chan *wire.Event{ch1, ch2} {
		select {
		case _, ok := <-ch:
			if ok {
				t.Errorf("sub %d: channel not closed", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("sub %d: timed out waiting for close", i)
		}
	}
}
