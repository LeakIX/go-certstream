package certstream

import (
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/LeakIX/go-certstream/types"
)

// Broadcaster Simple channel based pub/sub with buffer on clients
type Broadcaster struct {
	subs       atomic.Value
	mu         sync.Mutex
	bufferSize int64
}

func NewBroadcaster(bufferSize int64) *Broadcaster {
	b := &Broadcaster{
		bufferSize: bufferSize,
	}
	b.subs.Store(make([]chan []byte, 0))
	return b
}

func (b *Broadcaster) Join() chan []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan []byte, b.bufferSize)
	oldSubs := b.subs.Load().([]chan []byte)

	// Create a new slice and swap it in
	newSubs := append(oldSubs, ch)
	b.subs.Store(newSubs)
	return ch
}

func (b *Broadcaster) Leave(ch chan []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	oldSubs := b.subs.Load().([]chan []byte)
	newSubs := make([]chan []byte, 0, len(oldSubs))
	for _, s := range oldSubs {
		if s != ch {
			newSubs = append(newSubs, s)
		}
	}
	b.subs.Store(newSubs)
	close(ch)
}

func (b *Broadcaster) Submit(crtMsg types.CertStreamMessage) {
	data, err := json.Marshal(crtMsg)
	if err != nil {
		panic(err)
	}
	// Atomic Load: Extremely fast, zero lock contention
	subs := b.subs.Load().([]chan []byte)
	for _, ch := range subs {
		select {
		case ch <- data:
			// All good
		default:
			// Buffer full, skip
		}
	}
}
