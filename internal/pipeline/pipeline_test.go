package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/detect"
	"github.com/silentfabric-siem/silentfabric/internal/event"
)

type memSink struct {
	mu      sync.Mutex
	batches int
	events  []event.Event
	alerts  []detect.Alert
}

func (m *memSink) WriteEvents(_ context.Context, evs []event.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(evs) > 0 {
		m.batches++
	}
	m.events = append(m.events, evs...)
	return nil
}

func (m *memSink) WriteAlerts(_ context.Context, a []detect.Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, a...)
	return nil
}

func TestRunBatchesDetectsAndFlushesOnClose(t *testing.T) {
	engine, err := detect.LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	in := make(chan event.Event)
	sink := &memSink{}
	var notified int

	done := make(chan struct{})
	go func() {
		Run(context.Background(), in, engine, sink, Options{
			BatchSize:     2,
			FlushInterval: time.Hour,
			OnAlert:       func(detect.Alert) { notified++ },
		})
		close(done)
	}()

	in <- event.Event{Message: "Failed password for root from 10.0.0.1", Fields: map[string]string{"syslog.appname": "sshd"}}
	in <- event.Event{Message: "ordinary", Fields: map[string]string{}}
	in <- event.Event{Message: "leftover", Fields: map[string]string{}}
	close(in)
	<-done

	if len(sink.events) != 3 || sink.batches != 2 {
		t.Fatalf("events %d in %d batches, want 3 in 2", len(sink.events), sink.batches)
	}
	if len(sink.alerts) != 1 || notified != 1 {
		t.Fatalf("alerts %d, notified %d", len(sink.alerts), notified)
	}
}
