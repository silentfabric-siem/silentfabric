// Package pipeline connects ingest, detection and storage.
package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/detect"
	"github.com/silentfabric-siem/silentfabric/internal/event"
	"github.com/silentfabric-siem/silentfabric/internal/parse"
)

// Sink persists events and alerts. The ClickHouse store implements it.
type Sink interface {
	WriteEvents(ctx context.Context, evs []event.Event) error
	WriteAlerts(ctx context.Context, alerts []detect.Alert) error
}

// Options control batching. Larger batches are much cheaper for ClickHouse.
type Options struct {
	BatchSize     int
	FlushInterval time.Duration
	// OnAlert is called for every alert, e.g. to send a notification.
	OnAlert func(detect.Alert)
}

// Run consumes events until in is closed or ctx is cancelled, flushing any
// buffered data before it returns.
func Run(ctx context.Context, in <-chan event.Event, engine *detect.Engine, sink Sink, opts Options) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 5000
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}

	events := make([]event.Event, 0, opts.BatchSize)
	var alerts []detect.Alert

	flush := func() {
		// Use a fresh context so a shutdown still writes the final batch.
		fctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := sink.WriteEvents(fctx, events); err != nil {
			slog.Error("write events failed", "count", len(events), "err", err)
		}
		if err := sink.WriteAlerts(fctx, alerts); err != nil {
			slog.Error("write alerts failed", "count", len(alerts), "err", err)
		}
		events = events[:0]
		alerts = alerts[:0]
	}

	ticker := time.NewTicker(opts.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-in:
			if !ok {
				flush()
				return
			}
			parse.Normalize(&ev)
			matched, err := engine.Evaluate(ctx, &ev)
			if err != nil {
				slog.Warn("rule evaluation failed", "err", err)
			}
			for _, a := range matched {
				if opts.OnAlert != nil {
					opts.OnAlert(a)
				}
			}
			alerts = append(alerts, matched...)
			events = append(events, ev)
			if len(events) >= opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			if len(events) > 0 || len(alerts) > 0 {
				flush()
			}
		case <-ctx.Done():
			flush()
			return
		}
	}
}
